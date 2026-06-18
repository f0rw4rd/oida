# State Machine V2 Architecture Design Document

## Executive Summary

This design document outlines a robust state machine architecture for protocol fuzzing that can handle complex protocols like OPC UA, IEC 104, and similar industrial protocols. The design addresses six key gaps identified in the current implementation:

1. **StateContext** - Response data carrier between state transitions
2. **SequenceManager** - Bidirectional sequence support with fuzzing
3. **ServerMessageHook** - Handle server-initiated state changes
4. **Hierarchical States** - Parent/child relationships for partial reset
5. **Parallel State Dimensions** - Multiple orthogonal state variables
6. **CryptoStateManager** - Nonces, tokens, key derivation tracking

---

## 1. Architecture Overview

### Component Diagram

```
+------------------------------------------------------------------+
|                          StatefulFuzzer                           |
+------------------------------------------------------------------+
                                |
                                v
+------------------------------------------------------------------+
|                     ProtocolStateMachine                          |
|  +----------------+  +------------------+  +-------------------+  |
|  | StateDimension |  | StateDimension   |  | StateDimension    |  |
|  | (connection)   |  | (auth)           |  | (transaction)     |  |
|  +----------------+  +------------------+  +-------------------+  |
|                                |                                  |
|  +-----------------------------v------------------------------+   |
|  |                    StateContext                            |   |
|  |  +---------------+  +----------------+  +---------------+  |   |
|  |  | ResponseData  |  | SequenceManager |  | CryptoState  |  |   |
|  |  +---------------+  +----------------+  +---------------+  |   |
|  +------------------------------------------------------------+   |
|                                                                   |
|  +-----------------------------+  +----------------------------+  |
|  | ServerMessageHook          |  | HierarchicalStateTree      |  |
|  | (async message handling)   |  | (parent/child states)      |  |
|  +-----------------------------+  +----------------------------+  |
+------------------------------------------------------------------+
```

### Design Principles

1. **Backward Compatibility** - Simple protocols (Modbus, FTP) work with minimal configuration
2. **Progressive Complexity** - Complex features are opt-in, not required
3. **Composable** - Features can be used independently or combined
4. **Fuzzable** - All state-related values can be fuzzed (sequences, tokens, nonces)

---

## 2. Core Classes

### 2.1 StateContext - Response Data Carrier

```python
@dataclass
class ResponseData:
    """Parsed response data from server."""
    raw: bytes = b""
    parsed: Dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.now)
    response_code: Optional[int] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


class StateContext:
    """Carries state data between transitions and across requests.

    Key Features:
    - Key-value storage for arbitrary state data
    - Named response storage keyed by operation name
    - Protocol sequence trackers
    - Cryptographic state manager
    - Parent context for hierarchical state inheritance

    Example:
        ctx = StateContext()
        ctx.set("secure_channel_id", response.channel_id)
        ctx.set_response("OPN", ResponseData(raw=response.raw, parsed={...}))

        # Later
        channel_id = ctx.get("secure_channel_id")
    """
```

### 2.2 SequenceManager - Bidirectional Sequence Support

```python
@dataclass
class SequenceConfig:
    """Configuration for a sequence number."""
    name: str
    initial: int = 0
    min_value: int = 0
    max_value: int = 0xFFFF
    increment: int = 1
    direction: SequenceDirection = SequenceDirection.SEND
    wrap_behavior: str = "modulo"  # "modulo", "saturate", "error"
    fuzzable: bool = True


class SequenceManager:
    """Manages protocol sequence numbers with fuzzing support.

    Example (IEC 104):
        seq_mgr = SequenceManager("iec104")
        seq_mgr.add_sequence(SequenceConfig(
            name="send_seq",
            max_value=0x7FFF,
            increment=2,  # IEC104 increments by 2
            direction=SequenceDirection.SEND
        ))

        # Normal operation
        send_seq = seq_mgr.get_and_increment("send_seq")

        # Fuzzing: test sequence boundary
        seq_mgr.fuzz_sequence("send_seq", strategy="boundary")

        # Fuzzing: inject specific invalid value
        seq_mgr.inject_value("send_seq", 0xDEAD)

    Fuzz Strategies:
        - "boundary": Test min/max/wrap values
        - "random": Random values within range
        - "replay": Replay previous values
        - "skip": Skip sequence numbers
        - "reverse": Decrement instead of increment
        - "zero": Always return zero
        - "max": Always return max value
    """
```

### 2.3 ProtocolState (Enhanced) - Hierarchical Support

```python
class ProtocolState:
    """Protocol state with hierarchical support.

    New Features:
    - parent/children for hierarchy
    - on_enter/on_exit callbacks with context
    - Timeout handling with recovery

    Example (OPC UA):
        connected = ProtocolState("CONNECTED", state_type=StateType.CONNECTION)

        hello_complete = ProtocolState(
            name="HELLO_COMPLETE",
            parent=connected,
            setup=lambda ctx: send_hello(ctx),
            timeout=5.0,
        )

        secure_channel = ProtocolState(
            name="SECURE_CHANNEL",
            parent=hello_complete,
            setup=lambda ctx: open_channel(ctx),
            validation=lambda ctx: validate_channel(ctx),
        )
    """
```

### 2.4 ParallelStateMachine - Multiple State Dimensions

```python
class StateDimension:
    """A single dimension of protocol state."""
    name: str
    states: Dict[str, DimensionState]
    current_state: str


class ParallelStateMachine:
    """State machine with multiple parallel dimensions.

    Example (IEC 104):
        psm = ParallelStateMachine()

        psm.add_dimension(StateDimension("connection", "DISCONNECTED"))
        psm.add_dimension(StateDimension("flow_control", "NORMAL"))

        # Transition single dimension
        psm.transition("connection", "CONNECTED")

        # Check compound state
        if psm.matches(connection="DATA_TRANSFER", flow_control="NORMAL"):
            # Ready for data
            pass
    """
```

### 2.5 CryptoStateManager - Security State

```python
class CryptoStateManager:
    """Manages cryptographic state for protocol fuzzing.

    Features:
    - Nonce generation and tracking
    - Token storage with expiry and refresh
    - Key derivation and storage
    - Fuzz support for all crypto values

    Example (OPC UA):
        crypto = CryptoStateManager()

        # Generate client nonce
        client_nonce = crypto.generate_nonce("client_nonce", length=32)

        # Store server nonce
        crypto.set_nonce("server_nonce", server_response.nonce)

        # Store security token with refresh
        crypto.set_token("security_token", TokenState(
            value=response.token,
            expires_at=datetime.now() + timedelta(hours=1),
            refresh_callback=lambda: refresh_channel()
        ))

        # Fuzz nonce
        crypto.fuzz_nonce("client_nonce", strategy="zero")
    """
```

### 2.6 ServerMessageHook - Server-Initiated State Changes

```python
class ServerMessageHook:
    """Handles server-initiated messages and state changes.

    Example (IEC 104):
        hook = ServerMessageHook()

        # Auto-respond to TESTFR
        hook.register_handler("TESTFR_ACT",
            lambda msg, ctx: (send_testfr_con(), None))

        # Handle STOPDT by updating state
        def handle_stopdt(msg, ctx):
            ctx.set("data_transfer_active", False)
            return (None, "DATA_TRANSFER_STOPPED")
        hook.register_handler("STOPDT_ACT", handle_stopdt)
    """
```

---

## 3. Usage Examples

### 3.1 OPC UA with Full State Machine V2

```python
class OPCUAFuzzerV2(StatefulFuzzer):
    def __init__(self, config):
        super().__init__(config)
        self.state_context = StateContext()
        self._setup_sequences()
        self._setup_crypto()
        self._setup_server_hooks()

    def _setup_sequences(self):
        seq_mgr = SequenceManager("opcua")
        seq_mgr.add_sequence(SequenceConfig(
            name="sequence_number",
            initial=1,
            max_value=0xFFFFFFFF,
            direction=SequenceDirection.BOTH
        ))
        seq_mgr.add_sequence(SequenceConfig(
            name="request_id",
            initial=1,
            max_value=0xFFFFFFFF,
            direction=SequenceDirection.SEND
        ))
        self.state_context.register_sequence_manager("default", seq_mgr)

    def _open_secure_channel(self, ctx: StateContext) -> bool:
        seq_mgr = ctx.get_sequence_manager()
        crypto = ctx.crypto

        # Generate client nonce
        client_nonce = crypto.generate_nonce("client_nonce", length=32)

        # Get sequence numbers
        seq_num = seq_mgr.get_and_increment("sequence_number")
        req_id = seq_mgr.get_and_increment("request_id")

        # Send and receive...

        # Store response data in context
        ctx.set("secure_channel_id", response.channel_id)
        crypto.set_nonce("server_nonce", response.server_nonce)
        crypto.set_token("security_token", TokenState(...))

        return True
```

### 3.2 IEC 104 with Parallel Dimensions

```python
class IEC104FuzzerV2(StatefulFuzzer):
    def __init__(self, config):
        super().__init__(config)
        self.state_context = StateContext()
        self._setup_sequences()
        self._setup_parallel_states()
        self._setup_server_hooks()

    def _setup_sequences(self):
        seq_mgr = SequenceManager("iec104")
        seq_mgr.add_sequence(SequenceConfig(
            name="send_seq",
            max_value=0x7FFF,
            increment=2,
            direction=SequenceDirection.SEND
        ))
        seq_mgr.add_sequence(SequenceConfig(
            name="recv_seq",
            max_value=0x7FFF,
            increment=2,
            direction=SequenceDirection.RECEIVE
        ))
        self.state_context.register_sequence_manager("default", seq_mgr)

    def _setup_parallel_states(self):
        self.parallel_sm = ParallelStateMachine()

        # Connection dimension
        conn_dim = StateDimension("connection", "DISCONNECTED")
        conn_dim.add_state(DimensionState("DISCONNECTED", ["CONNECTED"]))
        conn_dim.add_state(DimensionState("CONNECTED", ["DATA_TRANSFER"]))
        conn_dim.add_state(DimensionState("DATA_TRANSFER", ["CONNECTED"]))
        self.parallel_sm.add_dimension(conn_dim)

        # Flow control dimension
        flow_dim = StateDimension("flow_control", "NORMAL")
        flow_dim.add_state(DimensionState("NORMAL", ["WAITING_ACK", "STOPPED"]))
        flow_dim.add_state(DimensionState("WAITING_ACK", ["NORMAL", "TIMEOUT"]))
        self.parallel_sm.add_dimension(flow_dim)

    def _setup_server_hooks(self):
        self.server_hook = ServerMessageHook()

        # Auto-respond to TESTFR
        self.server_hook.register_handler("TESTFR_ACT",
            lambda msg, ctx: (b'\x68\x04\x83\x00\x00\x00', None))

        # Handle STOPDT
        self.server_hook.register_handler("STOPDT_ACT",
            lambda msg, ctx: (b'\x68\x04\x23\x00\x00\x00', "CONNECTED"))
```

---

## 4. Migration Path

### Phase 1: Add StateContext (1-2 days)
- Add StateContext class
- Optional parameter in StatefulFuzzer
- Existing protocols unchanged

### Phase 2: Add SequenceManager (2-3 days)
- Add SequenceManager class
- Integrate with StateContext
- Update OPC UA and IEC 104

### Phase 3: Add ServerMessageHook (1-2 days)
- Add ServerMessageHook class
- Add to connection classes
- Update protocols with async messages

### Phase 4: Add Hierarchical States (2-3 days)
- Enhance ProtocolState
- Add HierarchicalStateMachine
- Update OPC UA

### Phase 5: Add Parallel Dimensions (2 days)
- Add StateDimension and ParallelStateMachine
- Update IEC 104

### Phase 6: Add CryptoStateManager (2 days)
- Add CryptoStateManager class
- Integrate with StateContext
- Update OPC UA

**Total Effort: ~12-15 days**

---

## 5. New Files

| File | Purpose |
|------|---------|
| `core/session/state_context.py` | StateContext, ResponseData |
| `core/session/sequence.py` | SequenceManager, SequenceConfig |
| `core/session/crypto_state.py` | CryptoStateManager, NonceState, TokenState |
| `core/session/server_hook.py` | ServerMessageHook, AsyncMessageReceiver |
| `core/session/state_dimension.py` | StateDimension, ParallelStateMachine |

## 6. Files to Update

| File | Changes |
|------|---------|
| `core/session/state_machine.py` | Add hierarchical support |
| `core/stateful_fuzzer.py` | Integrate new components |
| `protocols/opcua.py` | Use StateContext, SequenceManager, CryptoState |
| `protocols/iec104.py` | Use StateContext, SequenceManager, ParallelStateMachine |
