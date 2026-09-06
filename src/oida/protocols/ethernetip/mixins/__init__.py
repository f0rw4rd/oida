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

from .controller_info import ControllerInfoMixin
from .enip_commands import EnipCommandsMixin
from .attacks import AttacksMixin
from .discovery import DiscoveryMixin
from .cip_objects import CipObjectsMixin
from .cip_security import CipSecurityMixin
from .network_parsers import NetworkParsersMixin
from .advanced_parsers import AdvancedParsersMixin
from .class_explorer import ClassExplorerMixin
from .write_test import WriteTestMixin
from .fuzz import FuzzMixin
from .security_analysis import SecurityAnalysisMixin

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
