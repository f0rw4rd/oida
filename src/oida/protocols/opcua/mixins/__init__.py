"""
OPC UA Mixin classes for modular functionality.

These mixins are used by the main opcua class in nxc_connection.py to provide
specific functionality while keeping the codebase modular.
"""

from .discovery import DiscoveryMixin
from .browse import BrowseMixin
from .security import SecurityMixin
from .methods import MethodsMixin
from .fuzz import FuzzMixin
from .history import HistoryMixin
from .files import FilesMixin
from .credentials import CredentialsMixin
from .subscriptions import SubscriptionsMixin
from .writes import WritesMixin

__all__ = [
    "DiscoveryMixin",
    "BrowseMixin",
    "SecurityMixin",
    "MethodsMixin",
    "FuzzMixin",
    "HistoryMixin",
    "FilesMixin",
    "CredentialsMixin",
    "SubscriptionsMixin",
    "WritesMixin",
]
