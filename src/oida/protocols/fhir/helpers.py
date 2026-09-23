"""
FHIR Helpers

Constants, lazy imports, and utility functions shared by the FHIR module.
"""

import os

from oida.utils.lazy_import import lazy_import

# =========================================================================
# FHIR Server Vendor/Product Identification
# =========================================================================

FHIR_VENDOR_MAP = {
    # Major EMR/EHR Systems
    "EPIC": ("Epic Systems", "Epic FHIR Server"),
    "EPICCARE": ("Epic Systems", "EpicCare"),
    "MYCHART": ("Epic Systems", "MyChart FHIR API"),
    "CERNER": ("Cerner Corporation", "Millennium FHIR"),
    "POWERCHART": ("Cerner Corporation", "PowerChart FHIR"),
    "ORACLE HEALTH": ("Oracle Health", "Cerner FHIR"),
    "MEDITECH": ("Meditech", "Expanse FHIR"),
    "EXPANSE": ("Meditech", "Expanse FHIR Server"),
    "ALLSCRIPTS": ("Allscripts", "FHIR API"),
    "ATHENA": ("Athenahealth", "athenaOne FHIR"),
    "ATHENAHEALTH": ("Athenahealth", "athenaOne FHIR"),
    "NEXTGEN": ("NextGen Healthcare", "NextGen FHIR"),
    "ECLINICALWORKS": ("eClinicalWorks", "eCW FHIR"),
    "ECW": ("eClinicalWorks", "eCW FHIR"),
    # Open Source FHIR Servers
    "HAPI": ("HAPI FHIR", "HAPI FHIR Server"),
    "HAPI FHIR": ("HAPI FHIR", "HAPI FHIR Server"),
    "SMILE CDR": ("Smile CDR", "Smile CDR"),
    "FIRELY": ("Firely", "Vonk FHIR Server"),
    "VONK": ("Firely", "Vonk FHIR Server"),
    "SPARK": ("Firely", "Spark FHIR Server"),
    "ASYMMETRIK": ("Asymmetrik", "Node FHIR Server"),
    "IBM": ("IBM", "IBM FHIR Server"),
    "IBM FHIR": ("IBM", "IBM FHIR Server"),
    "LINUXFORHEALTH": ("IBM", "LinuxForHealth FHIR"),
    # Cloud Platforms
    "MICROSOFT": ("Microsoft", "Azure FHIR Server"),
    "AZURE": ("Microsoft", "Azure API for FHIR"),
    "AZURE API FOR FHIR": ("Microsoft", "Azure API for FHIR"),
    "AZURE HEALTH DATA SERVICES": ("Microsoft", "Azure Health Data Services"),
    "GOOGLE": ("Google", "Cloud Healthcare API"),
    "GOOGLE CLOUD": ("Google", "Cloud Healthcare API"),
    "AWS": ("Amazon", "AWS HealthLake"),
    "HEALTHLAKE": ("Amazon", "AWS HealthLake"),
    # Health Information Exchanges
    "COMMONWELL": ("CommonWell", "CommonWell FHIR"),
    "CAREQUALITY": ("Carequality", "Carequality FHIR"),
    "TEFCA": ("ONC", "TEFCA FHIR Gateway"),
    # Specialty Systems
    "ONCOCLINIC": ("OncoClinics", "Oncology FHIR"),
    "REDOX": ("Redox", "Redox FHIR Engine"),
    "HEALTH GORILLA": ("Health Gorilla", "Health Gorilla FHIR"),
    "PARTICLE": ("Particle Health", "Particle FHIR"),
    "1UP": ("1upHealth", "1upHealth FHIR"),
    "FLEXPA": ("Flexpa", "Flexpa FHIR"),
    # Pharmacy/PBM
    "SURESCRIPTS": ("Surescripts", "Surescripts FHIR"),
    "RXNORM": ("NLM", "RxNorm FHIR"),
    # Test/Development
    "TEST": ("Test System", "Development/Test"),
    "DEV": ("Development", "Development System"),
    "SYNTHEA": ("MITRE", "Synthea Test Data"),
    "LOGICA": ("Logica Health", "Logica Sandbox"),
    "SMART": ("SMART Health IT", "SMART on FHIR"),
}

# Security modes supported by FHIR servers
_SECURITY_BASE = "http://terminology.hl7.org/CodeSystem/restful-security-service"
FHIR_SECURITY_MODES = {
    "none": "No security (anonymous access)",
    f"{_SECURITY_BASE}|SMART-on-FHIR": "SMART on FHIR OAuth2",
    f"{_SECURITY_BASE}|OAuth": "OAuth2",
    f"{_SECURITY_BASE}|Basic": "HTTP Basic Auth",
    f"{_SECURITY_BASE}|NTLM": "NTLM Auth",
    f"{_SECURITY_BASE}|Certificates": "Client Certificates",
}

# =========================================================================
# Lazy Imports
# =========================================================================

# _fhirclient keeps a private handle because is_fhirclient_available() reads
# its .is_available attribute directly (see below).
_fhirclient = lazy_import("fhirclient.client", "FHIR")
fhirclient = _fhirclient

# _fhirabstractbase is read directly by _get_fhir_validation_error(); it needs
# no public alias.
_fhirabstractbase = lazy_import("fhirclient.models.fhirabstractbase", "FHIR")

# Individual model modules (lazy; access via __getattr__ triggers load)
capabilitystatement = lazy_import("fhirclient.models.capabilitystatement", "FHIR")
patient = lazy_import("fhirclient.models.patient", "FHIR")
observation = lazy_import("fhirclient.models.observation", "FHIR")
medicationrequest = lazy_import("fhirclient.models.medicationrequest", "FHIR")
condition = lazy_import("fhirclient.models.condition", "FHIR")
encounter = lazy_import("fhirclient.models.encounter", "FHIR")
procedure = lazy_import("fhirclient.models.procedure", "FHIR")
allergyintolerance = lazy_import("fhirclient.models.allergyintolerance", "FHIR")
immunization = lazy_import("fhirclient.models.immunization", "FHIR")
diagnosticreport = lazy_import("fhirclient.models.diagnosticreport", "FHIR")
documentreference = lazy_import("fhirclient.models.documentreference", "FHIR")

# Additional resource types for expanded search
practitioner = lazy_import("fhirclient.models.practitioner", "FHIR")
organization = lazy_import("fhirclient.models.organization", "FHIR")
location = lazy_import("fhirclient.models.location", "FHIR")
device = lazy_import("fhirclient.models.device", "FHIR")
servicerequest = lazy_import("fhirclient.models.servicerequest", "FHIR")


# =========================================================================
# Utility Functions
# =========================================================================


def _get_fhir_validation_error():
    """Get FHIRValidationError class for exception handling.

    Only called once fhirclient is confirmed available, so the symbol
    always resolves.
    """
    return _fhirabstractbase.FHIRValidationError


def is_fhirclient_available() -> bool:
    """Check if fhirclient is available without raising exception."""
    return _fhirclient.is_available


def validate_credential_path(file_path: str) -> str:
    """Validate a credential file path, blocking directory traversal.

    Rejects paths containing '..' components and resolves the path to
    an absolute location.  This prevents user-supplied paths from
    reading arbitrary files outside expected directories.

    Returns the resolved absolute path.
    Raises ValueError if the path is unsafe.
    """
    if ".." in os.path.normpath(file_path).split(os.sep):
        raise ValueError(f"Path traversal blocked: '{file_path}' contains '..'")

    # Realpath fully canonicalizes the path, so a post-resolve '..' check can
    # never fire — the pre-normpath check above is the real traversal guard.
    return os.path.realpath(file_path)
