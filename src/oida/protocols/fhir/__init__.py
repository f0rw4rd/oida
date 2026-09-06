"""
FHIR R4 Protocol Scanner

Scans FHIR (Fast Healthcare Interoperability Resources) R4 endpoints for:
- CapabilityStatement discovery (server metadata)
- Resource search (Patient, Observation, Medication, etc.)
- Security assessment (authentication, authorization)
- Vendor fingerprinting (Epic, Cerner, HAPI, etc.)

CLI examples:
    oida fhir https://fhir.example.com/r4         # Basic capability discovery
    oida fhir https://fhir.example.com/r4 --caps  # Get CapabilityStatement
    oida fhir https://fhir.example.com/r4 --search-patients --max-results 10
    oida fhir https://fhir.example.com/r4 --search-observations --patient-id PT001
    oida fhir https://fhir.example.com/r4 --test-auth
    oida fhir https://fhir.example.com/r4 --token "Bearer xyz..." --search-patients
"""

# Re-export the NXC-style connection class (mixin-based)
from .nxc_connection import fhir

# Re-export constants and utilities used by tests and external code
from .helpers import (
    FHIR_SECURITY_MODES,
    FHIR_VENDOR_MAP,
    is_fhirclient_available,
)

__all__ = [
    "fhir",
    "FHIR_VENDOR_MAP",
    "FHIR_SECURITY_MODES",
    "is_fhirclient_available",
]
