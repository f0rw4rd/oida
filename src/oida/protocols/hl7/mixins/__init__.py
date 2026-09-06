"""
HL7 v2 Protocol Mixins

This package contains mixin classes that provide specific functionality
for the HL7 NXC connection class. Each mixin handles a logical group
of related operations.

Mixins:
    - MessageMixin: ADT, ORU, ORM, SIU, MDM message creation/sending
    - QueryMixin: QRY/QBP query message construction and sending
    - PharmacyMixin: RDE, RAS, RGV, RDS pharmacy messages
    - ResponseMixin: Response parsing, data extraction
    - EnumMixin: Provider, application, location enumeration
    - ProbeMixin: Operation probing
    - MasterFileMixin: MFN/MFQ master file operations
    - SpecialQueryMixin: QBP special queries (WhoAmI, tabular, immunization)
    - FinancialMixin: BAR/DFT financial messages
    - DeviceMixin: IHE PCD Patient Care Device messages
    - FuzzMixin: Message fuzzing
    - SecurityMixin: Security analysis
    - ContinuationMixin: Continuation/fragmentation handling
"""

from .message import MessageMixin
from .query import QueryMixin
from .pharmacy import PharmacyMixin
from .response import ResponseMixin
from .enum import EnumMixin
from .probe import ProbeMixin
from .master_file import MasterFileMixin
from .special_query import SpecialQueryMixin
from .financial import FinancialMixin
from .device import DeviceMixin
from .fuzz import FuzzMixin
from .security import SecurityMixin
from .continuation import ContinuationMixin

__all__ = [
    "MessageMixin",
    "QueryMixin",
    "PharmacyMixin",
    "ResponseMixin",
    "EnumMixin",
    "ProbeMixin",
    "MasterFileMixin",
    "SpecialQueryMixin",
    "FinancialMixin",
    "DeviceMixin",
    "FuzzMixin",
    "SecurityMixin",
    "ContinuationMixin",
]
