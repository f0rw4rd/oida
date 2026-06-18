"""Sequence manager for bidirectional protocol sequence tracking.

Provides SequenceManager for tracking protocol sequence numbers with
wrap-around, direction-aware incrementing, and fuzzing support.
"""

from dataclasses import dataclass
from typing import Dict, List, Tuple
from enum import Enum, auto


class SequenceDirection(Enum):
    """Direction of sequence number increment."""

    SEND = auto()  # Incremented when sending
    RECEIVE = auto()  # Incremented when receiving
    BOTH = auto()  # Incremented in both directions


@dataclass
class SequenceConfig:
    """Configuration for a sequence number.

    Attributes:
        name: Sequence name (e.g., "send_seq", "recv_seq")
        initial: Initial value
        min_value: Minimum allowed value
        max_value: Maximum allowed value (wraps around)
        increment: Normal increment amount
        direction: When to increment (SEND, RECEIVE, BOTH)
        wrap_behavior: How to handle wrap ("modulo", "saturate", "error")
        fuzzable: Whether this sequence can be fuzzed
    """

    name: str
    initial: int = 0
    min_value: int = 0
    max_value: int = 0xFFFF
    increment: int = 1
    direction: SequenceDirection = SequenceDirection.SEND
    wrap_behavior: str = "modulo"
    fuzzable: bool = True


class SequenceManager:
    """Manages protocol sequence numbers with fuzzing support.

    Example:
        seq_mgr = SequenceManager("iec104")
        seq_mgr.add_sequence(SequenceConfig(
            name="send_seq",
            max_value=0x7FFF,
            increment=2,
            direction=SequenceDirection.SEND
        ))

        send_seq = seq_mgr.get_and_increment("send_seq")
    """

    def __init__(self, name: str = "default"):
        """Initialize sequence manager.

        Args:
            name: Manager name for logging
        """
        self.name = name
        self._sequences: Dict[str, SequenceConfig] = {}
        self._current_values: Dict[str, int] = {}
        self._history: List[Tuple[str, str, int, int]] = []

    def add_sequence(self, config: SequenceConfig) -> None:
        """Add a sequence configuration.

        Args:
            config: Sequence configuration
        """
        self._sequences[config.name] = config
        self._current_values[config.name] = config.initial

    def get(self, name: str) -> int:
        """Get current sequence value without incrementing.

        Args:
            name: Sequence name

        Returns:
            Current sequence value
        """
        if name not in self._current_values:
            raise KeyError(f"Unknown sequence: {name}")
        return self._current_values[name]

    def get_and_increment(self, name: str) -> int:
        """Get current value and increment for next use.

        Args:
            name: Sequence name

        Returns:
            Current sequence value (before increment)
        """
        if name not in self._sequences:
            raise KeyError(f"Unknown sequence: {name}")

        config = self._sequences[name]
        current = self._current_values[name]

        # Calculate new value
        new_value = current + config.increment
        if new_value > config.max_value:
            if config.wrap_behavior == "modulo":
                range_size = config.max_value - config.min_value + 1
                new_value = config.min_value + ((new_value - config.min_value) % range_size)
            elif config.wrap_behavior == "saturate":
                new_value = config.max_value
            else:
                raise ValueError(f"Sequence {name} overflow")

        self._current_values[name] = new_value
        self._history.append((name, "increment", current, new_value))
        return current

    def set(self, name: str, value: int) -> None:
        """Set sequence to specific value.

        Args:
            name: Sequence name
            value: New value
        """
        if name not in self._sequences:
            raise KeyError(f"Unknown sequence: {name}")
        old = self._current_values[name]
        self._current_values[name] = value
        self._history.append((name, "set", old, value))

    def reset(self) -> None:
        """Reset all sequences to initial values."""
        for name, config in self._sequences.items():
            self._current_values[name] = config.initial
        self._history.clear()

    def to_dict(self) -> Dict:
        """Serialize for logging."""
        return {
            "name": self.name,
            "sequences": {
                name: {
                    "current": self._current_values[name],
                    "max": cfg.max_value,
                }
                for name, cfg in self._sequences.items()
            },
        }

    def __repr__(self) -> str:
        return f"SequenceManager(name={self.name}, sequences={list(self._sequences.keys())})"
