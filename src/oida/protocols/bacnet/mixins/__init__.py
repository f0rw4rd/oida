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

from oida.protocols.bacnet.mixins.connection import ConnectionMixin
from oida.protocols.bacnet.mixins.discovery import DiscoveryMixin
from oida.protocols.bacnet.mixins.objects import ObjectsMixin
from oida.protocols.bacnet.mixins.properties import PropertiesMixin
from oida.protocols.bacnet.mixins.files import FilesMixin
from oida.protocols.bacnet.mixins.security import SecurityMixin
from oida.protocols.bacnet.mixins.network import NetworkMixin
from oida.protocols.bacnet.mixins.monitoring import MonitoringMixin
from oida.protocols.bacnet.mixins.state import StateMixin
from oida.protocols.bacnet.mixins.export import ExportMixin
from oida.protocols.bacnet.mixins.call import CallMixin
from oida.protocols.bacnet.mixins.sc import SCMixin

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
    "CallMixin",
    "SCMixin",
]
