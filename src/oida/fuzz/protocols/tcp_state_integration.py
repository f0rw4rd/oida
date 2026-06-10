"""
TCP State Machine Integration - Active state tracking during fuzzing

This module provides state machine integration for TCP fuzzing by bridging
boofuzz's packet-level callbacks to the central StateMachine framework
(src/oida/fuzz/core/session/state_machine.py).

The TCPStateTracker is a thin adapter that:
1. Parses TCP headers from outgoing/incoming packets
2. Determines the appropriate state transition based on TCP flags
3. Delegates all state tracking to self.fuzzer.state_machine

The central StateMachine (created by TCPFuzzer._define_state_machine()) is
the single source of truth for TCP state. This module never maintains its
own parallel state.

Usage:
    class TCPFuzzer(BaseFuzzer, StatefulTCPFuzzerMixin):
        def __init__(self, config):
            super().__init__(config)
            self._init_state_tracking()

        def fuzz_all(self):
            self.state_tracker.register_callbacks()
            super().fuzz_all()
"""

from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Dict, Optional, Tuple
import struct
import logging

from ..core.session.state_machine import StateTransitionError

logger = logging.getLogger(__name__)


class TCPState(Enum):
    """TCP connection states — convenience enum mapping to central StateMachine state names.

    Each member's .name matches the corresponding ProtocolState.name in the
    central StateMachine created by TCPFuzzer._define_state_machine().
    """

    CLOSED = auto()
    LISTEN = auto()
    SYN_SENT = auto()
    SYN_RECEIVED = auto()
    ESTABLISHED = auto()
    FIN_WAIT_1 = auto()
    FIN_WAIT_2 = auto()
    CLOSE_WAIT = auto()
    CLOSING = auto()
    LAST_ACK = auto()
    TIME_WAIT = auto()


class TCPFlags:
    """TCP flag constants"""

    FIN = 0x01
    SYN = 0x02
    RST = 0x04
    PSH = 0x08
    ACK = 0x10
    URG = 0x20
    ECE = 0x40
    CWR = 0x80


@dataclass
class TCPPacketInfo:
    """Parsed TCP packet information"""

    src_port: int = 0
    dst_port: int = 0
    seq_num: int = 0
    ack_num: int = 0
    data_offset: int = 5
    flags: int = 0
    window: int = 0
    checksum: int = 0
    urgent_ptr: int = 0
    options: bytes = field(default_factory=bytes)
    payload: bytes = field(default_factory=bytes)

    @property
    def has_syn(self) -> bool:
        return bool(self.flags & TCPFlags.SYN)

    @property
    def has_ack(self) -> bool:
        return bool(self.flags & TCPFlags.ACK)

    @property
    def has_fin(self) -> bool:
        return bool(self.flags & TCPFlags.FIN)

    @property
    def has_rst(self) -> bool:
        return bool(self.flags & TCPFlags.RST)

    @property
    def has_psh(self) -> bool:
        return bool(self.flags & TCPFlags.PSH)

    def flag_string(self) -> str:
        """Human-readable flag string like 'SYN,ACK'"""
        flags = []
        if self.has_syn:
            flags.append("SYN")
        if self.has_ack:
            flags.append("ACK")
        if self.has_fin:
            flags.append("FIN")
        if self.has_rst:
            flags.append("RST")
        if self.has_psh:
            flags.append("PSH")
        if self.flags & TCPFlags.URG:
            flags.append("URG")
        if self.flags & TCPFlags.ECE:
            flags.append("ECE")
        if self.flags & TCPFlags.CWR:
            flags.append("CWR")
        return ",".join(flags) if flags else "NONE"


class TCPStateTracker:
    """
    TCP state tracker that delegates to the central StateMachine.

    This is an adapter between boofuzz's packet-level callbacks and the
    central StateMachine framework. It parses TCP headers to determine
    which state transitions should occur, then calls
    self.fuzzer.state_machine.transition_to() or set_state_no_setup().

    The central StateMachine (self.fuzzer.state_machine) is the single
    source of truth for current state, transition history, and validation.

    Features:
    - Parses outgoing/incoming TCP packets to determine state transitions
    - Delegates all state management to the central StateMachine
    - Supports both enforcement and attack modes via StateMachine's
      allow_invalid_transitions flag
    - Handles connection reuse (resets state to CLOSED on new connections)

    Integration Points:
    - pre_send callback: Determine state from request name or packet flags
    - post_send callback: Parse response to update state (raw socket mode)
    """

    # Map request names to expected state transitions
    # (expected_current_state, next_state_after_send)
    # None means "any state" / no transition
    REQUEST_STATE_MAP: Dict[str, Tuple[Optional[str], Optional[str]]] = {
        "TCP_SYN": ("CLOSED", "SYN_SENT"),
        "TCP_SYN_ACK": ("SYN_RECEIVED", "SYN_RECEIVED"),  # Server sends, stays
        "TCP_Data": ("ESTABLISHED", "ESTABLISHED"),
        "TCP_FIN": ("ESTABLISHED", "FIN_WAIT_1"),
        "TCP_SACK": ("ESTABLISHED", "ESTABLISHED"),
        "TCP_MPTCP": ("ESTABLISHED", "ESTABLISHED"),
        "TCP_Auth": ("ESTABLISHED", "ESTABLISHED"),
        # Attack patterns - can be sent from any state, no transition
        "TCP_THC_Flag_Fuzz": (None, None),
        "TCP_Invalid_States": (None, None),
        "TCP_Reserved_Bit_Test": (None, None),
        "TCP_State_Confusion": (None, None),
    }

    def __init__(self, fuzzer, enforce_states: bool = False):
        """
        Initialize TCP state tracker.

        Args:
            fuzzer: The TCPFuzzer instance (must have .state_machine set)
            enforce_states: If True, reject invalid state transitions.
                           If False, log warnings but allow (for attack testing).
        """
        self.fuzzer = fuzzer
        self.enforce_states = enforce_states
        self._connection_count = 0

        # Track invalid transitions that were attempted (for attack reporting)
        self._invalid_transition_count = 0

    @property
    def _sm(self):
        """Shortcut to the central state machine."""
        return self.fuzzer.state_machine

    @property
    def current_state(self) -> TCPState:
        """Current state as TCPState enum, read from the central StateMachine."""
        if self._sm:
            state_name = self._sm.get_current_state_name()
            try:
                return TCPState[state_name]
            except KeyError:
                return TCPState.CLOSED
        return TCPState.CLOSED

    @property
    def current_state_name(self) -> str:
        """Current state name as string, read from the central StateMachine."""
        if self._sm:
            return self._sm.get_current_state_name()
        return "CLOSED"

    def register_callbacks(self) -> None:
        """
        Register callbacks with boofuzz session for active state tracking.

        Call this in fuzz_all() before running the fuzzer.
        """
        session = self.fuzzer.session

        # Configure the central state machine's enforcement mode
        if self._sm:
            if self.enforce_states:
                self._sm.allow_invalid_transitions = False
            else:
                self._sm.allow_invalid_transitions = True

        # For standard TCP sockets, OS handles handshake automatically
        # Start in ESTABLISHED state when connection opens
        if not getattr(self.fuzzer, "use_raw_socket", False):
            self._transition_to("ESTABLISHED", "os_handshake_complete", force=True)
            self.fuzzer.log.debug("Standard TCP socket: auto-transitioned to ESTABLISHED")

        # Pre-send: Validate/update state before sending packet
        def pre_send_callback(target, fuzz_data_logger, session, sock):
            self._on_pre_send(session)

        session._callback_monitor.on_pre_send.append(pre_send_callback)

        # Post-send: Parse response (if any) and update state
        def post_send_callback(target, fuzz_data_logger, session, *args, **kwargs):
            self._on_post_send(session)

        session.register_post_test_case_callback(post_send_callback)

        self.fuzzer.log.display(f"TCP state tracker registered (enforce={self.enforce_states})")

    def _transition_to(
        self,
        state_name: str,
        trigger: str,
        packet_info: Optional[TCPPacketInfo] = None,
        force: bool = False,
    ) -> bool:
        """
        Transition the central StateMachine to a new state.

        Args:
            state_name: Target state name (e.g. "SYN_SENT", "ESTABLISHED")
            trigger: What triggered the transition (for logging)
            packet_info: Optional packet that triggered this
            force: If True, bypass validation

        Returns:
            True if transition successful, False if blocked
        """
        if not self._sm:
            self.fuzzer.log.debug(f"No state machine, cannot transition to {state_name}")
            return False

        old_state = self._sm.get_current_state_name()

        # Same-state transitions (e.g. ESTABLISHED -> ESTABLISHED for data) are no-ops
        if old_state == state_name:
            self.fuzzer.log.debug(f"State: {old_state} (staying, trigger={trigger})")
            return True

        try:
            self._sm.transition_to(state_name, force=force)
            self.fuzzer.log.debug(f"State: {old_state} -> {state_name} ({trigger})")
            return True
        except StateTransitionError as e:
            self._invalid_transition_count += 1
            if self.enforce_states:
                self.fuzzer.log.warning(
                    f"Invalid state transition blocked: {old_state} -> {state_name} ({trigger})"
                )
                return False
            else:
                # In attack mode, force the transition through
                self.fuzzer.log.debug(
                    f"Invalid state transition (allowed): {old_state} -> {state_name} ({trigger}): {e}"
                )
                try:
                    self._sm.set_state_no_setup(state_name)
                    return True
                except StateTransitionError:
                    return False

    def _on_pre_send(self, session) -> None:
        """
        Called before each packet is sent.

        Updates state based on the request type being sent.
        """
        # Get current request name
        request_name = None
        if hasattr(session, "fuzz_node") and session.fuzz_node:
            request_name = session.fuzz_node.name

        if not request_name:
            return

        # Check if this is a new connection (connection was reset)
        # boofuzz may have closed and reopened the socket
        if self._should_reset_state(session):
            self._reset_state("connection_reset")

        # Get expected state mapping for this request
        mapping = self.REQUEST_STATE_MAP.get(request_name)

        if mapping:
            expected_state, next_state = mapping

            # Validate current state (if expected_state is specified)
            if expected_state is not None and self.current_state_name != expected_state:
                self._handle_state_mismatch(request_name, expected_state)

            # Transition to next state (if specified)
            if next_state is not None:
                self._transition_to(next_state, f"sent_{request_name}")
        else:
            # Unknown request - try to infer from packet flags
            self._infer_state_from_packet(session, request_name)

    def _on_post_send(self, session) -> None:
        """
        Called after each packet is sent.

        Parses response (if any) to update state.
        """
        # In raw socket mode, we might have a response to parse
        if hasattr(self.fuzzer, "use_raw_socket") and self.fuzzer.use_raw_socket:
            self._parse_response(session)

    def _should_reset_state(self, session) -> bool:
        """Check if connection was reset and state should be reset."""
        target = session.targets[0] if session.targets else None
        if target and hasattr(target, "_target_connection"):
            conn = target._target_connection
            if hasattr(conn, "_connection_id"):
                if conn._connection_id != self._connection_count:
                    self._connection_count = conn._connection_id
                    return True
        return False

    def _reset_state(self, reason: str) -> None:
        """Reset state machine to CLOSED state."""
        old_state = self.current_state_name

        if self._sm:
            try:
                self._sm.set_state_no_setup("CLOSED")
            except StateTransitionError:
                # If CLOSED doesn't exist in states somehow, force it
                self._sm.transition_to("CLOSED", force=True)

        self.fuzzer.log.debug(f"State reset: {old_state} -> CLOSED ({reason})")

    def _handle_state_mismatch(self, request_name: str, expected_state: str) -> None:
        """Handle case where current state doesn't match expected."""
        current = self.current_state_name
        if self.enforce_states:
            self.fuzzer.log.warning(
                f"State mismatch for {request_name}: expected {expected_state}, current {current}"
            )
        else:
            self.fuzzer.log.debug(
                f"State mismatch (allowed) for {request_name}: "
                f"expected {expected_state}, current {current}"
            )

    def _infer_state_from_packet(self, session, request_name: str) -> None:
        """
        Infer state transition from packet being sent.

        Parses the outgoing packet to determine flags and updates state accordingly.
        """
        if not hasattr(session, "last_send") or not session.last_send:
            return

        packet_data = session.last_send
        if not isinstance(packet_data, bytes):
            try:
                packet_data = bytes(packet_data)
            except (TypeError, ValueError) as e:
                logger.debug(f"Failed to get packet_data: {e}")
                return

        if len(packet_data) < 20:
            return

        packet_info = parse_tcp_header(packet_data)
        if not packet_info:
            return

        new_state = self._state_for_outgoing_flags(packet_info.flags)
        if new_state:
            self._transition_to(new_state, f"sent_{packet_info.flag_string()}", packet_info)

    def _state_for_outgoing_flags(self, flags: int) -> Optional[str]:
        """
        Determine state transition based on outgoing packet flags.

        Returns state name string (matching central StateMachine) or None.
        """
        has_syn = bool(flags & TCPFlags.SYN)
        has_ack = bool(flags & TCPFlags.ACK)
        has_fin = bool(flags & TCPFlags.FIN)
        has_rst = bool(flags & TCPFlags.RST)

        current = self.current_state_name

        if has_rst:
            return "CLOSED"

        if current == "CLOSED":
            if has_syn and not has_ack:
                return "SYN_SENT"

        elif current == "SYN_SENT":
            if has_syn and has_ack:
                return "SYN_RECEIVED"  # Simultaneous open
            elif has_ack and not has_syn:
                return "ESTABLISHED"  # After receiving SYN-ACK

        elif current == "ESTABLISHED":
            if has_fin:
                return "FIN_WAIT_1"

        elif current == "FIN_WAIT_1":
            if has_ack and not has_fin:
                return "FIN_WAIT_2"

        elif current == "CLOSE_WAIT":
            if has_fin:
                return "LAST_ACK"

        return None

    def _parse_response(self, session) -> None:
        """
        Parse response packet and update state.

        Used in raw socket mode where we can see the actual responses.
        """
        target = session.targets[0] if session.targets else None
        if not target:
            return

        conn = target._target_connection
        if not hasattr(conn, "last_recv") or not conn.last_recv:
            return

        response = conn.last_recv
        if len(response) < 20:
            return

        packet_info = parse_tcp_header(response)
        if not packet_info:
            return

        new_state = self._state_for_incoming_flags(packet_info.flags)
        if new_state:
            self._transition_to(new_state, f"recv_{packet_info.flag_string()}", packet_info)

    def _state_for_incoming_flags(self, flags: int) -> Optional[str]:
        """
        Determine state transition based on incoming packet flags.

        Returns state name string (matching central StateMachine) or None.
        """
        has_syn = bool(flags & TCPFlags.SYN)
        has_ack = bool(flags & TCPFlags.ACK)
        has_fin = bool(flags & TCPFlags.FIN)
        has_rst = bool(flags & TCPFlags.RST)

        current = self.current_state_name

        if has_rst:
            return "CLOSED"

        if current == "SYN_SENT":
            if has_syn and has_ack:
                return "ESTABLISHED"  # Received SYN-ACK
            elif has_syn and not has_ack:
                return "SYN_RECEIVED"  # Simultaneous open

        elif current == "ESTABLISHED":
            if has_fin:
                return "CLOSE_WAIT"

        elif current == "FIN_WAIT_1":
            if has_fin and has_ack:
                return "TIME_WAIT"
            elif has_fin:
                return "CLOSING"
            elif has_ack:
                return "FIN_WAIT_2"

        elif current == "FIN_WAIT_2":
            if has_fin:
                return "TIME_WAIT"

        elif current == "CLOSING":
            if has_ack:
                return "TIME_WAIT"

        elif current == "LAST_ACK":
            if has_ack:
                return "CLOSED"

        return None

    # Public API

    def get_transition_summary(self) -> str:
        """
        Get human-readable transition summary from the central StateMachine.

        Returns:
            Formatted string with transition history
        """
        if not self._sm:
            return "TCP State Tracking Summary\nNo state machine configured"

        transition_log = self._sm.get_transition_log()
        current = self._sm.get_current_state_name()

        lines = ["TCP State Tracking Summary"]
        lines.append(f"Current state: {current}")
        lines.append(f"Total transitions: {len(transition_log)}")
        lines.append(f"Invalid transitions: {self._invalid_transition_count}")
        lines.append("")
        lines.append("Recent transitions:")

        for t in transition_log[-10:]:
            forced_str = " [FORCED]" if t.get("forced") else ""
            lines.append(f"  {t['from']} -> {t['to']}{forced_str}")

        return "\n".join(lines)


def parse_tcp_header(data: bytes) -> Optional[TCPPacketInfo]:
    """
    Parse TCP header from raw bytes.

    Args:
        data: Raw packet data (TCP header + payload)

    Returns:
        TCPPacketInfo or None if parsing fails
    """
    if len(data) < 20:
        return None

    try:
        # TCP header format (20 bytes minimum):
        # 0-1: Source port
        # 2-3: Destination port
        # 4-7: Sequence number
        # 8-11: Acknowledgment number
        # 12: Data offset (4 bits) + Reserved (4 bits)
        # 13: Flags
        # 14-15: Window
        # 16-17: Checksum
        # 18-19: Urgent pointer

        src_port, dst_port = struct.unpack("!HH", data[0:4])
        seq_num, ack_num = struct.unpack("!II", data[4:12])

        data_offset_byte = data[12]
        data_offset = (data_offset_byte >> 4) & 0x0F

        flags = data[13]
        window = struct.unpack("!H", data[14:16])[0]
        checksum = struct.unpack("!H", data[16:18])[0]
        urgent_ptr = struct.unpack("!H", data[18:20])[0]

        header_len = data_offset * 4

        options = b""
        if header_len > 20 and len(data) >= header_len:
            options = data[20:header_len]

        payload = b""
        if len(data) > header_len:
            payload = data[header_len:]

        return TCPPacketInfo(
            src_port=src_port,
            dst_port=dst_port,
            seq_num=seq_num,
            ack_num=ack_num,
            data_offset=data_offset,
            flags=flags,
            window=window,
            checksum=checksum,
            urgent_ptr=urgent_ptr,
            options=options,
            payload=payload,
        )
    except (struct.error, IndexError) as e:
        logger.debug(f"Operation failed: {e}")
        return None


class StatefulTCPFuzzerMixin:
    """
    Mixin class to add stateful TCP fuzzing capabilities.

    Bridges the TCPFuzzer to the central StateMachine via TCPStateTracker.
    The state_tracker is a thin adapter that parses TCP packets and drives
    transitions on self.state_machine (the central StateMachine).

    Add to TCPFuzzer class:

        class TCPFuzzer(BaseFuzzer, StatefulTCPFuzzerMixin):
            def __init__(self, config):
                super().__init__(config)
                self._init_state_tracking()
    """

    def _init_state_tracking(self, enforce_states: bool = False) -> None:
        """Initialize state tracking adapter for this fuzzer.

        Creates a TCPStateTracker that delegates to self.state_machine.
        """
        self.state_tracker = TCPStateTracker(self, enforce_states=enforce_states)
