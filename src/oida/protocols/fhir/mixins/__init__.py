"""
FHIR Protocol Mixins

Modular functionality groups for the FHIR NXC-style connection class.
"""

from .search import SearchMixin
from .security import SecurityMixin
from .crud import CRUDMixin

__all__ = [
    "SearchMixin",
    "SecurityMixin",
    "CRUDMixin",
]
