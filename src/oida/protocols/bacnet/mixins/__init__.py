"""
BACnet Protocol Mixins

This package contains mixin classes that provide specific functionality
for the BACnet NXC connection class. Each mixin handles a logical group
of related operations.

Mixins:
    - ConnectionMixin: BAC0/bacpypes3 connection lifecycle
    - DiscoveryMixin: Who-Is, device discovery, identify
    - ObjectsMixin: Object/service enumeration
    - PropertiesMixin: Property read/write, present values
    - FilesMixin: File enumeration, AtomicReadFile
    - SecurityMixin: Auth check, brute force, DCC, reinit, BACnet/SC
    - NetworkMixin: BBMD, FDT, routers, remote networks
    - MonitoringMixin: Schedules, calendars, alarms, trendlogs, priority, life safety
    - StateMixin: Dump, diff, monitor loop
    - ExportMixin: Result export, helpers
"""

from .connection import ConnectionMixin
from .discovery import DiscoveryMixin
from .objects import ObjectsMixin
from .properties import PropertiesMixin
from .files import FilesMixin
from .security import SecurityMixin
from .network import NetworkMixin
from .monitoring import MonitoringMixin
from .state import StateMixin
from .export import ExportMixin

__all__ = [
    "ConnectionMixin",
    "DiscoveryMixin",
    "ObjectsMixin",
    "PropertiesMixin",
    "FilesMixin",
    "SecurityMixin",
    "NetworkMixin",
    "MonitoringMixin",
    "StateMixin",
    "ExportMixin",
]
