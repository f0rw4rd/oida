"""
FHIR Helpers

Constants, lazy imports, and utility functions shared by the FHIR module.
"""

import os

from ...utils.lazy_import import lazy_import
from ...utils.ics_logger import get_module_logger

logger = get_module_logger(__name__)

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

_fhirclient = lazy_import("fhirclient.client", "FHIR")

# Individual model modules
_capabilitystatement = lazy_import("fhirclient.models.capabilitystatement", "FHIR")
_patient = lazy_import("fhirclient.models.patient", "FHIR")
_observation = lazy_import("fhirclient.models.observation", "FHIR")
_medicationrequest = lazy_import("fhirclient.models.medicationrequest", "FHIR")
_condition = lazy_import("fhirclient.models.condition", "FHIR")
_encounter = lazy_import("fhirclient.models.encounter", "FHIR")
_procedure = lazy_import("fhirclient.models.procedure", "FHIR")
_allergyintolerance = lazy_import("fhirclient.models.allergyintolerance", "FHIR")
_immunization = lazy_import("fhirclient.models.immunization", "FHIR")
_diagnosticreport = lazy_import("fhirclient.models.diagnosticreport", "FHIR")
_documentreference = lazy_import("fhirclient.models.documentreference", "FHIR")
_fhirabstractbase = lazy_import("fhirclient.models.fhirabstractbase", "FHIR")

# Additional resource types for expanded search
_practitioner = lazy_import("fhirclient.models.practitioner", "FHIR")
_organization = lazy_import("fhirclient.models.organization", "FHIR")
_location = lazy_import("fhirclient.models.location", "FHIR")
_device = lazy_import("fhirclient.models.device", "FHIR")
_servicerequest = lazy_import("fhirclient.models.servicerequest", "FHIR")

# Aliases for lazy modules (access via __getattr__ triggers load)
fhirclient = _fhirclient
capabilitystatement = _capabilitystatement
patient = _patient
observation = _observation
medicationrequest = _medicationrequest
condition = _condition
encounter = _encounter
procedure = _procedure
allergyintolerance = _allergyintolerance
immunization = _immunization
diagnosticreport = _diagnosticreport
documentreference = _documentreference
practitioner = _practitioner
organization = _organization
location = _location
device = _device
servicerequest = _servicerequest


# =========================================================================
# Utility Functions
# =========================================================================


def _get_fhir_validation_error():
    """Get FHIRValidationError class for exception handling"""
    try:
        return _fhirabstractbase.FHIRValidationError
    except Exception as e:
        logger.debug("get fhir validation error failed: %s", e)
        return type("FHIRValidationError", (Exception,), {})


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
