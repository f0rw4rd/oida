"""Session management layer for protocol fuzzing.

This module provides session management:
- Test case recording and replay
- Protocol state machine
- State context for response data propagation
- Logging configuration
- Command execution
"""

from oida.fuzz.core.session.logging import (
    get_logger,
    setup_logging,
    set_level,
    CleanFormatter,
    StandardFormatter,
)
from oida.fuzz.core.session.commands import CommandRunner, RealCommandRunner, MockCommandRunner
from oida.fuzz.core.session.state_machine import (
    StateMachine,
    ProtocolState,
    TransitionRule,
    StateType,
    StateTransitionError,
    create_auth_state_machine,
)
from oida.fuzz.core.session.state_context import StateContext, ResponseData
from oida.fuzz.core.session.sequence import SequenceManager, SequenceConfig, SequenceDirection
from oida.fuzz.core.session.crypto_state import (
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
        from oida.fuzz.core.session.manager import TestCaseManager, RollingBuffer, create_fuzzer

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
