"""
OPC UA Mixin classes for modular functionality.

These mixins are used by the main opcua class in cli_runner.py to provide
specific functionality while keeping the codebase modular.
"""

from oida.protocols.opcua.mixins.discovery import DiscoveryMixin
from oida.protocols.opcua.mixins.browse import BrowseMixin
from oida.protocols.opcua.mixins.security import SecurityMixin
from oida.protocols.opcua.mixins.methods import MethodsMixin
from oida.protocols.opcua.mixins.fuzz import FuzzMixin
from oida.protocols.opcua.mixins.history import HistoryMixin
from oida.protocols.opcua.mixins.files import FilesMixin
from oida.protocols.opcua.mixins.credentials import CredentialsMixin
from oida.protocols.opcua.mixins.subscriptions import SubscriptionsMixin
from oida.protocols.opcua.mixins.writes import WritesMixin

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
