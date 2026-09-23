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

from oida.protocols.hl7.mixins.message import MessageMixin
from oida.protocols.hl7.mixins.query import QueryMixin
from oida.protocols.hl7.mixins.pharmacy import PharmacyMixin
from oida.protocols.hl7.mixins.response import ResponseMixin
from oida.protocols.hl7.mixins.enum import EnumMixin
from oida.protocols.hl7.mixins.probe import ProbeMixin
from oida.protocols.hl7.mixins.master_file import MasterFileMixin
from oida.protocols.hl7.mixins.special_query import SpecialQueryMixin
from oida.protocols.hl7.mixins.financial import FinancialMixin
from oida.protocols.hl7.mixins.device import DeviceMixin
from oida.protocols.hl7.mixins.fuzz import FuzzMixin
from oida.protocols.hl7.mixins.security import SecurityMixin
from oida.protocols.hl7.mixins.continuation import ContinuationMixin

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
