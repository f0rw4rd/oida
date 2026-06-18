"""
Interaction tracking infrastructure.

ProtocolInteraction and core tracking are now integrated into
PySharkListenerBase. This module re-exports for backward compatibility.
"""

# Re-export from the base class where they now live
from .pyshark_base import ProtocolInteraction

__all__ = ["ProtocolInteraction"]
