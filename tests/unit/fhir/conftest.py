"""
Conftest for FHIR unit tests.

Installs mock fhirclient modules into sys.modules so that LazyModule
objects in oida.protocols.fhir.helpers resolve successfully even when
fhirclient is not installed.  This allows @patch() decorators on
module-level lazy imports (e.g. ``@patch("oida.protocols.fhir.mixins.crud.patient")``)
to work without triggering DependencyError.
"""

import sys
from types import ModuleType
from unittest.mock import MagicMock

import pytest

# Map of fhirclient module path -> dict of class/attribute names to pre-populate
# with MagicMock objects.  This ensures that code like ``patient.Patient`` or
# ``observation.Observation`` works even when the module is not patched by the
# specific test.
_FHIRCLIENT_MODULES = {
    "fhirclient": {},
    "fhirclient.client": {"FHIRClient": None},
    "fhirclient.models": {},
    "fhirclient.models.capabilitystatement": {"CapabilityStatement": None},
    "fhirclient.models.patient": {"Patient": None},
    "fhirclient.models.observation": {"Observation": None},
    "fhirclient.models.medicationrequest": {"MedicationRequest": None},
    "fhirclient.models.condition": {"Condition": None},
    "fhirclient.models.encounter": {"Encounter": None},
    "fhirclient.models.procedure": {"Procedure": None},
    "fhirclient.models.allergyintolerance": {"AllergyIntolerance": None},
    "fhirclient.models.immunization": {"Immunization": None},
    "fhirclient.models.diagnosticreport": {"DiagnosticReport": None},
    "fhirclient.models.documentreference": {"DocumentReference": None},
    "fhirclient.models.fhirabstractbase": {
        "FHIRValidationError": type("FHIRValidationError", (Exception,), {}),
    },
    "fhirclient.models.practitioner": {"Practitioner": None},
    "fhirclient.models.organization": {"Organization": None},
    "fhirclient.models.location": {"Location": None},
    "fhirclient.models.device": {"Device": None},
    "fhirclient.models.servicerequest": {"ServiceRequest": None},
    "fhirclient.models.humanname": {"HumanName": None},
    "fhirclient.models.fhirdate": {"FHIRDate": None},
}


def _is_fhirclient_installed():
    """Check whether fhirclient is actually importable."""
    try:
        import importlib

        importlib.import_module("fhirclient")
        return True
    except ImportError:
        return False


# Cache the result once per process.
_FHIRCLIENT_AVAILABLE = _is_fhirclient_installed()


@pytest.fixture(autouse=True)
def _mock_fhirclient_modules():
    """Inject mock fhirclient modules into sys.modules for every test.

    This fixture:
    1. Saves any pre-existing sys.modules entries for fhirclient paths
    2. Installs ModuleType objects with MagicMock class stubs for each path
    3. Resets LazyModule state so they pick up the mocks
    4. Restores original sys.modules state on teardown
    """
    if _FHIRCLIENT_AVAILABLE:
        yield
        return

    saved = {}

    # Create and install mock module objects with class-level MagicMock stubs.
    for mod_path, class_attrs in _FHIRCLIENT_MODULES.items():
        saved[mod_path] = sys.modules.get(mod_path, None)
        mock_mod = ModuleType(mod_path)
        mock_mod.__path__ = []
        mock_mod.__package__ = mod_path
        for attr_name, attr_val in class_attrs.items():
            if attr_val is None:
                attr_val = MagicMock(name=f"{mod_path}.{attr_name}")
            setattr(mock_mod, attr_name, attr_val)
        sys.modules[mod_path] = mock_mod

    # Reset LazyModule instances in helpers so they re-resolve from sys.modules.
    from oida.protocols.fhir import helpers

    _lazy_attrs = [
        "_fhirclient",
        "_capabilitystatement",
        "_patient",
        "_observation",
        "_medicationrequest",
        "_condition",
        "_encounter",
        "_procedure",
        "_allergyintolerance",
        "_immunization",
        "_diagnosticreport",
        "_documentreference",
        "_fhirabstractbase",
        "_practitioner",
        "_organization",
        "_location",
        "_device",
        "_servicerequest",
    ]
    for attr_name in _lazy_attrs:
        lazy_obj = getattr(helpers, attr_name, None)
        if lazy_obj is not None and hasattr(lazy_obj, "_loaded"):
            lazy_obj._loaded = False
            lazy_obj._module = None
            lazy_obj._available = None

    # Public aliases are the same LazyModule objects.
    public_aliases = [a.lstrip("_") for a in _lazy_attrs]
    for alias in public_aliases:
        lazy_obj = getattr(helpers, alias, None)
        if lazy_obj is not None and hasattr(lazy_obj, "_loaded"):
            lazy_obj._loaded = False
            lazy_obj._module = None
            lazy_obj._available = None

    yield

    # Restore sys.modules
    for mod_path in _FHIRCLIENT_MODULES:
        if saved[mod_path] is None:
            sys.modules.pop(mod_path, None)
        else:
            sys.modules[mod_path] = saved[mod_path]

    # Reset LazyModule state so other test suites are not affected
    for attr_name in _lazy_attrs:
        lazy_obj = getattr(helpers, attr_name, None)
        if lazy_obj is not None and hasattr(lazy_obj, "_loaded"):
            lazy_obj._loaded = False
            lazy_obj._module = None
            lazy_obj._available = None
