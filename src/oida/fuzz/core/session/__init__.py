"""Session management layer for protocol fuzzing.

This module provides session management:
- Test case recording and replay
- Protocol state machine
- State context for response data propagation
- Logging configuration
- Command execution
"""

from .logging import (
    get_logger,
    setup_logging,
    set_level,
    CleanFormatter,
    StandardFormatter,
)
from .commands import (
    CommandRunner,
    RealCommandRunner,
    MockCommandRunner,
)
from .state_machine import (
    StateMachine,
    ProtocolState,
    TransitionRule,
    StateType,
    StateTransitionError,
    create_auth_state_machine,
)
from .state_context import (
    StateContext,
    ResponseData,
)
from .sequence import (
    SequenceManager,
    SequenceConfig,
    SequenceDirection,
)
from .crypto_state import (
    CryptoStateManager,
    NonceState,
    TokenState,
    KeyState,
    NonceStrategy,
)


# Lazy import for manager to avoid circular dependency with protocols
def __getattr__(name):
    """Lazy load manager module to avoid circular imports."""
    if name in ("TestCaseManager", "RollingBuffer", "create_fuzzer"):
        from .manager import TestCaseManager, RollingBuffer, create_fuzzer

        if name == "TestCaseManager":
            return TestCaseManager
        elif name == "RollingBuffer":
            return RollingBuffer
        elif name == "create_fuzzer":
            return create_fuzzer
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = [
    # Logging
    "get_logger",
    "setup_logging",
    "set_level",
    "CleanFormatter",
    "StandardFormatter",
    # Commands
    "CommandRunner",
    "RealCommandRunner",
    "MockCommandRunner",
    # State machine
    "StateMachine",
    "ProtocolState",
    "TransitionRule",
    "StateType",
    "StateTransitionError",
    "create_auth_state_machine",
    # State context (Phase 1 of State Machine V2)
    "StateContext",
    "ResponseData",
    # Sequence manager
    "SequenceManager",
    "SequenceConfig",
    "SequenceDirection",
    # Crypto state
    "CryptoStateManager",
    "NonceState",
    "TokenState",
    "KeyState",
    "NonceStrategy",
    # Manager (lazy loaded)
    "TestCaseManager",
    "RollingBuffer",
    "create_fuzzer",
]
