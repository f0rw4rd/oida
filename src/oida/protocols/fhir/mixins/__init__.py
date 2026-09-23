"""
FHIR Protocol Mixins

Modular functionality groups for the FHIR NXC-style connection class.
"""

from oida.protocols.fhir.mixins.search import SearchMixin
from oida.protocols.fhir.mixins.security import SecurityMixin
from oida.protocols.fhir.mixins.crud import CRUDMixin

__all__ = [
    "SearchMixin",
    "SecurityMixin",
    "CRUDMixin",
]
