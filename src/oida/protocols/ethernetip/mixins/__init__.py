"""
EtherNet/IP Protocol Mixins

This package contains mixin classes that provide specific functionality
for the EtherNet/IP scanner class. Each mixin handles a logical group
of related operations.

Mixins:
    - ControllerInfoMixin: Controller mode, time, tag database, data types, dangerous tags
    - EnipCommandsMixin: ENIP packet building, parsing, session registration
    - AttacksMixin: CPU stop/crash, ethernet crash/reset
    - DiscoveryMixin: List identity, list services, list interfaces, broadcast discovery
    - CipObjectsMixin: Object enumeration, ports, chassis topology, backplane slots
    - CipSecurityMixin: CIP security detection, TLS support, certificate handling
    - NetworkParsersMixin: TCP/IP interface, ethernet link, assembly, time sync parsers
    - AdvancedParsersMixin: Message router, connection manager, parameter object, file operations
    - ClassExplorerMixin: Class discovery, attribute exploration
    - WriteTestMixin: Attribute write testing, permission checking
    - FuzzMixin: Attribute fuzzing
    - SecurityAnalysisMixin: Security analysis and reporting
"""

from oida.protocols.ethernetip.mixins.controller_info import ControllerInfoMixin
from oida.protocols.ethernetip.mixins.enip_commands import EnipCommandsMixin
from oida.protocols.ethernetip.mixins.attacks import AttacksMixin
from oida.protocols.ethernetip.mixins.discovery import DiscoveryMixin
from oida.protocols.ethernetip.mixins.cip_objects import CipObjectsMixin
from oida.protocols.ethernetip.mixins.cip_security import CipSecurityMixin
from oida.protocols.ethernetip.mixins.network_parsers import NetworkParsersMixin
from oida.protocols.ethernetip.mixins.advanced_parsers import AdvancedParsersMixin
from oida.protocols.ethernetip.mixins.class_explorer import ClassExplorerMixin
from oida.protocols.ethernetip.mixins.write_test import WriteTestMixin
from oida.protocols.ethernetip.mixins.fuzz import FuzzMixin
from oida.protocols.ethernetip.mixins.security_analysis import SecurityAnalysisMixin

__all__ = [
    "ControllerInfoMixin",
    "EnipCommandsMixin",
    "AttacksMixin",
    "DiscoveryMixin",
    "CipObjectsMixin",
    "CipSecurityMixin",
    "NetworkParsersMixin",
    "AdvancedParsersMixin",
    "ClassExplorerMixin",
    "WriteTestMixin",
    "FuzzMixin",
    "SecurityAnalysisMixin",
]
