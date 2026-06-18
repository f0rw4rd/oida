#!/usr/bin/env python3
"""
Mock FHIR R4 Server for testing OIDA FHIR scanner

Supports FHIR REST API testing:
- CapabilityStatement (/metadata)
- Patient search and read
- Observation search and read
- MedicationRequest search and read
- Condition search and read
- Encounter search and read
- Security testing (anonymous access, cross-patient access)

Provides realistic FHIR R4 responses for pentest reconnaissance.
"""

import json
import logging
import re
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

logging.basicConfig(level=logging.INFO)
log = logging.getLogger(__name__)

# Server configuration
SERVER_NAME = "OIDA Mock FHIR Server"
SERVER_VERSION = "1.0.0"
FHIR_VERSION = "4.0.1"
BASE_URL = "http://localhost:8080/fhir"

# Mock Patients
MOCK_PATIENTS = [
    {
        "id": "PT001",
        "identifier": [
            {"system": "http://hospital.local/mrn", "value": "MRN001"},
            {"system": "http://hl7.org/fhir/sid/us-ssn", "value": "123-45-6789"},
        ],
        "name": [{"use": "official", "family": "Doe", "given": ["John", "Michael"]}],
        "gender": "male",
        "birthDate": "1980-01-15",
        "address": [
            {
                "use": "home",
                "line": ["123 Main Street"],
                "city": "Anytown",
                "state": "ST",
                "postalCode": "12345",
                "country": "USA",
            }
        ],
        "telecom": [
            {"system": "phone", "value": "(555) 123-4567", "use": "home"},
            {"system": "email", "value": "john.doe@example.com"},
        ],
        "maritalStatus": {
            "coding": [
                {
                    "system": "http://terminology.hl7.org/CodeSystem/v3-MaritalStatus",
                    "code": "M",
                    "display": "Married",
                }
            ]
        },
    },
    {
        "id": "PT002",
        "identifier": [
            {"system": "http://hospital.local/mrn", "value": "MRN002"},
            {"system": "http://hl7.org/fhir/sid/us-ssn", "value": "234-56-7890"},
        ],
        "name": [{"use": "official", "family": "Smith", "given": ["Jane", "Ann"]}],
        "gender": "female",
        "birthDate": "1975-05-20",
        "address": [
            {
                "use": "home",
                "line": ["456 Oak Avenue"],
                "city": "Somewhere",
                "state": "ST",
                "postalCode": "23456",
                "country": "USA",
            }
        ],
        "telecom": [
            {"system": "phone", "value": "(555) 234-5678", "use": "mobile"},
            {"system": "email", "value": "jane.smith@example.com"},
        ],
        "maritalStatus": {
            "coding": [
                {
                    "system": "http://terminology.hl7.org/CodeSystem/v3-MaritalStatus",
                    "code": "S",
                    "display": "Never Married",
                }
            ]
        },
    },
    {
        "id": "PT003",
        "identifier": [
            {"system": "http://hospital.local/mrn", "value": "MRN003"},
        ],
        "name": [{"use": "official", "family": "Johnson", "given": ["Robert", "Lee"]}],
        "gender": "male",
        "birthDate": "1965-03-10",
        "address": [
            {
                "use": "home",
                "line": ["789 Elm Street"],
                "city": "Nowhere",
                "state": "ST",
                "postalCode": "34567",
                "country": "USA",
            }
        ],
        "telecom": [{"system": "phone", "value": "(555) 345-6789", "use": "home"}],
    },
    {
        "id": "PT004",
        "identifier": [
            {"system": "http://hospital.local/mrn", "value": "MRN004"},
        ],
        "name": [{"use": "official", "family": "Williams", "given": ["Mary", "Kate"]}],
        "gender": "female",
        "birthDate": "1990-07-25",
        "address": [
            {
                "use": "home",
                "line": ["321 Pine Road"],
                "city": "Elsewhere",
                "state": "ST",
                "postalCode": "45678",
                "country": "USA",
            }
        ],
        "telecom": [{"system": "phone", "value": "(555) 456-7890", "use": "mobile"}],
    },
    {
        "id": "PT005",
        "identifier": [
            {"system": "http://hospital.local/mrn", "value": "MRN005"},
        ],
        "name": [{"use": "official", "family": "Brown", "given": ["David", "James"]}],
        "gender": "male",
        "birthDate": "1955-12-30",
        "address": [
            {
                "use": "home",
                "line": ["654 Maple Drive"],
                "city": "Anywhere",
                "state": "ST",
                "postalCode": "56789",
                "country": "USA",
            }
        ],
        "telecom": [{"system": "phone", "value": "(555) 567-8901", "use": "home"}],
    },
]

# Mock Observations (vital signs, lab results)
MOCK_OBSERVATIONS = [
    {
        "id": "OBS001",
        "status": "final",
        "category": [
            {
                "coding": [
                    {
                        "system": "http://terminology.hl7.org/CodeSystem/observation-category",
                        "code": "vital-signs",
                        "display": "Vital Signs",
                    }
                ]
            }
        ],
        "code": {
            "coding": [{"system": "http://loinc.org", "code": "8867-4", "display": "Heart rate"}],
            "text": "Heart rate",
        },
        "subject": {"reference": "Patient/PT001"},
        "effectiveDateTime": "2024-01-15T10:30:00Z",
        "valueQuantity": {
            "value": 72,
            "unit": "beats/minute",
            "system": "http://unitsofmeasure.org",
            "code": "/min",
        },
    },
    {
        "id": "OBS002",
        "status": "final",
        "category": [
            {
                "coding": [
                    {
                        "system": "http://terminology.hl7.org/CodeSystem/observation-category",
                        "code": "vital-signs",
                        "display": "Vital Signs",
                    }
                ]
            }
        ],
        "code": {
            "coding": [
                {
                    "system": "http://loinc.org",
                    "code": "8480-6",
                    "display": "Systolic blood pressure",
                }
            ],
            "text": "Systolic BP",
        },
        "subject": {"reference": "Patient/PT001"},
        "effectiveDateTime": "2024-01-15T10:30:00Z",
        "valueQuantity": {
            "value": 120,
            "unit": "mmHg",
            "system": "http://unitsofmeasure.org",
            "code": "mm[Hg]",
        },
    },
    {
        "id": "OBS003",
        "status": "final",
        "category": [
            {
                "coding": [
                    {
                        "system": "http://terminology.hl7.org/CodeSystem/observation-category",
                        "code": "laboratory",
                        "display": "Laboratory",
                    }
                ]
            }
        ],
        "code": {
            "coding": [
                {
                    "system": "http://loinc.org",
                    "code": "2339-0",
                    "display": "Glucose [Mass/volume] in Blood",
                }
            ],
            "text": "Blood Glucose",
        },
        "subject": {"reference": "Patient/PT001"},
        "effectiveDateTime": "2024-01-15T08:00:00Z",
        "valueQuantity": {
            "value": 95,
            "unit": "mg/dL",
            "system": "http://unitsofmeasure.org",
            "code": "mg/dL",
        },
        "interpretation": [
            {
                "coding": [
                    {
                        "system": "http://terminology.hl7.org/CodeSystem/v3-ObservationInterpretation",
                        "code": "N",
                        "display": "Normal",
                    }
                ]
            }
        ],
    },
    {
        "id": "OBS004",
        "status": "final",
        "category": [
            {
                "coding": [
                    {
                        "system": "http://terminology.hl7.org/CodeSystem/observation-category",
                        "code": "laboratory",
                        "display": "Laboratory",
                    }
                ]
            }
        ],
        "code": {
            "coding": [
                {
                    "system": "http://loinc.org",
                    "code": "2093-3",
                    "display": "Cholesterol [Mass/volume] in Serum or Plasma",
                }
            ],
            "text": "Total Cholesterol",
        },
        "subject": {"reference": "Patient/PT002"},
        "effectiveDateTime": "2024-01-10T09:00:00Z",
        "valueQuantity": {
            "value": 210,
            "unit": "mg/dL",
            "system": "http://unitsofmeasure.org",
            "code": "mg/dL",
        },
        "interpretation": [
            {
                "coding": [
                    {
                        "system": "http://terminology.hl7.org/CodeSystem/v3-ObservationInterpretation",
                        "code": "H",
                        "display": "High",
                    }
                ]
            }
        ],
    },
    {
        "id": "OBS005",
        "status": "final",
        "category": [
            {
                "coding": [
                    {
                        "system": "http://terminology.hl7.org/CodeSystem/observation-category",
                        "code": "vital-signs",
                        "display": "Vital Signs",
                    }
                ]
            }
        ],
        "code": {
            "coding": [{"system": "http://loinc.org", "code": "29463-7", "display": "Body weight"}],
            "text": "Body Weight",
        },
        "subject": {"reference": "Patient/PT003"},
        "effectiveDateTime": "2024-01-12T14:00:00Z",
        "valueQuantity": {
            "value": 82.5,
            "unit": "kg",
            "system": "http://unitsofmeasure.org",
            "code": "kg",
        },
    },
]

# Mock MedicationRequests
MOCK_MEDICATIONS = [
    {
        "id": "MED001",
        "status": "active",
        "intent": "order",
        "medicationCodeableConcept": {
            "coding": [
                {
                    "system": "http://www.nlm.nih.gov/research/umls/rxnorm",
                    "code": "197361",
                    "display": "Lisinopril 10 MG Oral Tablet",
                }
            ],
            "text": "Lisinopril 10mg",
        },
        "subject": {"reference": "Patient/PT001"},
        "authoredOn": "2024-01-01",
        "dosageInstruction": [
            {
                "text": "Take 1 tablet by mouth daily",
                "timing": {"repeat": {"frequency": 1, "period": 1, "periodUnit": "d"}},
            }
        ],
    },
    {
        "id": "MED002",
        "status": "active",
        "intent": "order",
        "medicationCodeableConcept": {
            "coding": [
                {
                    "system": "http://www.nlm.nih.gov/research/umls/rxnorm",
                    "code": "860975",
                    "display": "Metformin 500 MG Oral Tablet",
                }
            ],
            "text": "Metformin 500mg",
        },
        "subject": {"reference": "Patient/PT001"},
        "authoredOn": "2024-01-01",
        "dosageInstruction": [
            {
                "text": "Take 1 tablet by mouth twice daily with meals",
                "timing": {"repeat": {"frequency": 2, "period": 1, "periodUnit": "d"}},
            }
        ],
    },
    {
        "id": "MED003",
        "status": "active",
        "intent": "order",
        "medicationCodeableConcept": {
            "coding": [
                {
                    "system": "http://www.nlm.nih.gov/research/umls/rxnorm",
                    "code": "310965",
                    "display": "Atorvastatin 20 MG Oral Tablet",
                }
            ],
            "text": "Atorvastatin 20mg",
        },
        "subject": {"reference": "Patient/PT002"},
        "authoredOn": "2024-01-10",
        "dosageInstruction": [
            {
                "text": "Take 1 tablet by mouth at bedtime",
                "timing": {"repeat": {"frequency": 1, "period": 1, "periodUnit": "d"}},
            }
        ],
    },
]

# Mock Conditions (diagnoses)
MOCK_CONDITIONS = [
    {
        "id": "CON001",
        "clinicalStatus": {
            "coding": [
                {
                    "system": "http://terminology.hl7.org/CodeSystem/condition-clinical",
                    "code": "active",
                    "display": "Active",
                }
            ]
        },
        "verificationStatus": {
            "coding": [
                {
                    "system": "http://terminology.hl7.org/CodeSystem/condition-ver-status",
                    "code": "confirmed",
                    "display": "Confirmed",
                }
            ]
        },
        "category": [
            {
                "coding": [
                    {
                        "system": "http://terminology.hl7.org/CodeSystem/condition-category",
                        "code": "encounter-diagnosis",
                        "display": "Encounter Diagnosis",
                    }
                ]
            }
        ],
        "code": {
            "coding": [
                {
                    "system": "http://snomed.info/sct",
                    "code": "73211009",
                    "display": "Diabetes mellitus (disorder)",
                }
            ],
            "text": "Type 2 Diabetes Mellitus",
        },
        "subject": {"reference": "Patient/PT001"},
        "onsetDateTime": "2020-05-15",
    },
    {
        "id": "CON002",
        "clinicalStatus": {
            "coding": [
                {
                    "system": "http://terminology.hl7.org/CodeSystem/condition-clinical",
                    "code": "active",
                    "display": "Active",
                }
            ]
        },
        "verificationStatus": {
            "coding": [
                {
                    "system": "http://terminology.hl7.org/CodeSystem/condition-ver-status",
                    "code": "confirmed",
                    "display": "Confirmed",
                }
            ]
        },
        "category": [
            {
                "coding": [
                    {
                        "system": "http://terminology.hl7.org/CodeSystem/condition-category",
                        "code": "encounter-diagnosis",
                        "display": "Encounter Diagnosis",
                    }
                ]
            }
        ],
        "code": {
            "coding": [
                {
                    "system": "http://snomed.info/sct",
                    "code": "38341003",
                    "display": "Hypertensive disorder (disorder)",
                }
            ],
            "text": "Essential Hypertension",
        },
        "subject": {"reference": "Patient/PT001"},
        "onsetDateTime": "2019-03-10",
    },
    {
        "id": "CON003",
        "clinicalStatus": {
            "coding": [
                {
                    "system": "http://terminology.hl7.org/CodeSystem/condition-clinical",
                    "code": "active",
                    "display": "Active",
                }
            ]
        },
        "verificationStatus": {
            "coding": [
                {
                    "system": "http://terminology.hl7.org/CodeSystem/condition-ver-status",
                    "code": "confirmed",
                    "display": "Confirmed",
                }
            ]
        },
        "category": [
            {
                "coding": [
                    {
                        "system": "http://terminology.hl7.org/CodeSystem/condition-category",
                        "code": "encounter-diagnosis",
                        "display": "Encounter Diagnosis",
                    }
                ]
            }
        ],
        "code": {
            "coding": [
                {
                    "system": "http://snomed.info/sct",
                    "code": "13644009",
                    "display": "Hypercholesterolemia (disorder)",
                }
            ],
            "text": "Hyperlipidemia",
        },
        "subject": {"reference": "Patient/PT002"},
        "onsetDateTime": "2023-06-20",
    },
]

# Mock Encounters
MOCK_ENCOUNTERS = [
    {
        "id": "ENC001",
        "status": "finished",
        "class": {
            "system": "http://terminology.hl7.org/CodeSystem/v3-ActCode",
            "code": "AMB",
            "display": "ambulatory",
        },
        "type": [
            {
                "coding": [
                    {
                        "system": "http://snomed.info/sct",
                        "code": "185349003",
                        "display": "Encounter for check up",
                    }
                ],
                "text": "Annual Physical",
            }
        ],
        "subject": {"reference": "Patient/PT001"},
        "period": {"start": "2024-01-15T09:00:00Z", "end": "2024-01-15T10:30:00Z"},
        "reasonCode": [
            {
                "coding": [
                    {
                        "system": "http://snomed.info/sct",
                        "code": "410620007",
                        "display": "Well adult (finding)",
                    }
                ],
                "text": "Wellness visit",
            }
        ],
    },
    {
        "id": "ENC002",
        "status": "finished",
        "class": {
            "system": "http://terminology.hl7.org/CodeSystem/v3-ActCode",
            "code": "AMB",
            "display": "ambulatory",
        },
        "type": [
            {
                "coding": [
                    {
                        "system": "http://snomed.info/sct",
                        "code": "390906007",
                        "display": "Follow-up encounter",
                    }
                ],
                "text": "Follow-up Visit",
            }
        ],
        "subject": {"reference": "Patient/PT002"},
        "period": {"start": "2024-01-10T14:00:00Z", "end": "2024-01-10T14:30:00Z"},
        "reasonCode": [
            {
                "coding": [
                    {
                        "system": "http://snomed.info/sct",
                        "code": "13644009",
                        "display": "Hypercholesterolemia",
                    }
                ],
                "text": "Cholesterol follow-up",
            }
        ],
    },
]

# Mock Procedures
MOCK_PROCEDURES = [
    {
        "id": "PROC001",
        "status": "completed",
        "code": {
            "coding": [
                {
                    "system": "http://snomed.info/sct",
                    "code": "174041007",
                    "display": "Appendectomy (procedure)",
                }
            ],
            "text": "Appendectomy",
        },
        "subject": {"reference": "Patient/PT003"},
        "performedDateTime": "2023-08-15T10:00:00Z",
    },
]

# Mock AllergyIntolerances
MOCK_ALLERGIES = [
    {
        "id": "ALL001",
        "clinicalStatus": {
            "coding": [
                {
                    "system": "http://terminology.hl7.org/CodeSystem/allergyintolerance-clinical",
                    "code": "active",
                    "display": "Active",
                }
            ]
        },
        "verificationStatus": {
            "coding": [
                {
                    "system": "http://terminology.hl7.org/CodeSystem/allergyintolerance-verification",
                    "code": "confirmed",
                    "display": "Confirmed",
                }
            ]
        },
        "type": "allergy",
        "category": ["medication"],
        "criticality": "high",
        "code": {
            "coding": [
                {
                    "system": "http://www.nlm.nih.gov/research/umls/rxnorm",
                    "code": "7980",
                    "display": "Penicillin",
                }
            ],
            "text": "Penicillin",
        },
        "patient": {"reference": "Patient/PT001"},
        "reaction": [
            {
                "manifestation": [
                    {
                        "coding": [
                            {
                                "system": "http://snomed.info/sct",
                                "code": "271807003",
                                "display": "Skin rash",
                            }
                        ]
                    }
                ],
                "severity": "severe",
            }
        ],
    },
    {
        "id": "ALL002",
        "clinicalStatus": {
            "coding": [
                {
                    "system": "http://terminology.hl7.org/CodeSystem/allergyintolerance-clinical",
                    "code": "active",
                    "display": "Active",
                }
            ]
        },
        "verificationStatus": {
            "coding": [
                {
                    "system": "http://terminology.hl7.org/CodeSystem/allergyintolerance-verification",
                    "code": "confirmed",
                    "display": "Confirmed",
                }
            ]
        },
        "type": "intolerance",
        "category": ["food"],
        "criticality": "low",
        "code": {
            "coding": [
                {
                    "system": "http://snomed.info/sct",
                    "code": "91935009",
                    "display": "Peanut (substance)",
                }
            ],
            "text": "Peanuts",
        },
        "patient": {"reference": "Patient/PT002"},
        "reaction": [
            {
                "manifestation": [
                    {
                        "coding": [
                            {
                                "system": "http://snomed.info/sct",
                                "code": "267036007",
                                "display": "Dyspnea",
                            }
                        ]
                    }
                ],
                "severity": "moderate",
            }
        ],
    },
]

# Mock Immunizations
MOCK_IMMUNIZATIONS = [
    {
        "id": "IMM001",
        "status": "completed",
        "vaccineCode": {
            "coding": [
                {
                    "system": "http://hl7.org/fhir/sid/cvx",
                    "code": "208",
                    "display": "COVID-19 mRNA vaccine",
                }
            ],
            "text": "COVID-19 Vaccine",
        },
        "patient": {"reference": "Patient/PT001"},
        "occurrenceDateTime": "2023-10-15",
        "lotNumber": "EL1234",
        "site": {
            "coding": [
                {
                    "system": "http://terminology.hl7.org/CodeSystem/v3-ActSite",
                    "code": "LA",
                    "display": "Left arm",
                }
            ]
        },
    },
    {
        "id": "IMM002",
        "status": "completed",
        "vaccineCode": {
            "coding": [
                {
                    "system": "http://hl7.org/fhir/sid/cvx",
                    "code": "141",
                    "display": "Influenza, seasonal, injectable",
                }
            ],
            "text": "Flu Shot",
        },
        "patient": {"reference": "Patient/PT001"},
        "occurrenceDateTime": "2023-11-01",
        "lotNumber": "FL5678",
    },
]


def create_resource(resource_type: str, data: dict) -> dict:
    """Wrap data in FHIR resource format"""
    return {
        "resourceType": resource_type,
        "id": data["id"],
        "meta": {
            "versionId": "1",
            "lastUpdated": datetime.now().isoformat() + "Z",
        },
        **{k: v for k, v in data.items() if k != "id"},
    }


def create_bundle(resources: list, total: int = None) -> dict:
    """Create a FHIR searchset Bundle"""
    if total is None:
        total = len(resources)

    return {
        "resourceType": "Bundle",
        "id": f"bundle-{datetime.now().strftime('%Y%m%d%H%M%S')}",
        "type": "searchset",
        "total": total,
        "link": [{"relation": "self", "url": BASE_URL}],
        "entry": [
            {
                "fullUrl": f"{BASE_URL}/{r['resourceType']}/{r['id']}",
                "resource": r,
                "search": {"mode": "match"},
            }
            for r in resources
        ],
    }


def create_capability_statement() -> dict:
    """Generate CapabilityStatement for the mock server"""
    return {
        "resourceType": "CapabilityStatement",
        "id": "mock-fhir-server",
        "url": f"{BASE_URL}/metadata",
        "version": SERVER_VERSION,
        "name": "MockFHIRServer",
        "title": SERVER_NAME,
        "status": "active",
        "experimental": True,
        "date": datetime.now().strftime("%Y-%m-%d"),
        "publisher": "OIDA Security Testing Framework",
        "description": "Mock FHIR R4 server for security testing",
        "kind": "instance",
        "software": {
            "name": SERVER_NAME,
            "version": SERVER_VERSION,
        },
        "implementation": {
            "description": "Mock FHIR server for OIDA testing",
            "url": BASE_URL,
        },
        "fhirVersion": FHIR_VERSION,
        "format": ["json", "xml"],
        "rest": [
            {
                "mode": "server",
                "documentation": "RESTful FHIR Server",
                "security": {
                    "cors": True,
                    "service": [
                        {
                            "coding": [
                                {
                                    "system": "http://terminology.hl7.org/CodeSystem/restful-security-service",
                                    "code": "SMART-on-FHIR",
                                    "display": "SMART on FHIR",
                                }
                            ],
                            "text": "OAuth2 using SMART on FHIR profile",
                        }
                    ],
                    "description": "Server supports SMART on FHIR authorization",
                    "extension": [
                        {
                            "url": "http://fhir-registry.smarthealthit.org/StructureDefinition/oauth-uris",
                            "extension": [
                                {"url": "authorize", "valueUri": f"{BASE_URL}/auth/authorize"},
                                {"url": "token", "valueUri": f"{BASE_URL}/auth/token"},
                            ],
                        }
                    ],
                },
                "resource": [
                    {
                        "type": "Patient",
                        "profile": "http://hl7.org/fhir/StructureDefinition/Patient",
                        "interaction": [
                            {"code": "read"},
                            {"code": "search-type"},
                        ],
                        "searchParam": [
                            {"name": "_id", "type": "token"},
                            {"name": "name", "type": "string"},
                            {"name": "birthdate", "type": "date"},
                            {"name": "gender", "type": "token"},
                            {"name": "identifier", "type": "token"},
                        ],
                    },
                    {
                        "type": "Observation",
                        "profile": "http://hl7.org/fhir/StructureDefinition/Observation",
                        "interaction": [
                            {"code": "read"},
                            {"code": "search-type"},
                        ],
                        "searchParam": [
                            {"name": "_id", "type": "token"},
                            {"name": "patient", "type": "reference"},
                            {"name": "category", "type": "token"},
                            {"name": "code", "type": "token"},
                            {"name": "date", "type": "date"},
                        ],
                    },
                    {
                        "type": "MedicationRequest",
                        "profile": "http://hl7.org/fhir/StructureDefinition/MedicationRequest",
                        "interaction": [
                            {"code": "read"},
                            {"code": "search-type"},
                        ],
                        "searchParam": [
                            {"name": "_id", "type": "token"},
                            {"name": "patient", "type": "reference"},
                            {"name": "status", "type": "token"},
                        ],
                    },
                    {
                        "type": "Condition",
                        "profile": "http://hl7.org/fhir/StructureDefinition/Condition",
                        "interaction": [
                            {"code": "read"},
                            {"code": "search-type"},
                        ],
                        "searchParam": [
                            {"name": "_id", "type": "token"},
                            {"name": "patient", "type": "reference"},
                            {"name": "clinical-status", "type": "token"},
                        ],
                    },
                    {
                        "type": "Encounter",
                        "profile": "http://hl7.org/fhir/StructureDefinition/Encounter",
                        "interaction": [
                            {"code": "read"},
                            {"code": "search-type"},
                        ],
                        "searchParam": [
                            {"name": "_id", "type": "token"},
                            {"name": "patient", "type": "reference"},
                            {"name": "status", "type": "token"},
                        ],
                    },
                    {
                        "type": "Procedure",
                        "profile": "http://hl7.org/fhir/StructureDefinition/Procedure",
                        "interaction": [
                            {"code": "read"},
                            {"code": "search-type"},
                        ],
                        "searchParam": [
                            {"name": "_id", "type": "token"},
                            {"name": "patient", "type": "reference"},
                        ],
                    },
                    {
                        "type": "AllergyIntolerance",
                        "profile": "http://hl7.org/fhir/StructureDefinition/AllergyIntolerance",
                        "interaction": [
                            {"code": "read"},
                            {"code": "search-type"},
                        ],
                        "searchParam": [
                            {"name": "_id", "type": "token"},
                            {"name": "patient", "type": "reference"},
                        ],
                    },
                    {
                        "type": "Immunization",
                        "profile": "http://hl7.org/fhir/StructureDefinition/Immunization",
                        "interaction": [
                            {"code": "read"},
                            {"code": "search-type"},
                        ],
                        "searchParam": [
                            {"name": "_id", "type": "token"},
                            {"name": "patient", "type": "reference"},
                        ],
                    },
                    {
                        "type": "DiagnosticReport",
                        "profile": "http://hl7.org/fhir/StructureDefinition/DiagnosticReport",
                        "interaction": [
                            {"code": "read"},
                            {"code": "search-type"},
                        ],
                        "searchParam": [
                            {"name": "_id", "type": "token"},
                            {"name": "patient", "type": "reference"},
                        ],
                    },
                    {
                        "type": "DocumentReference",
                        "profile": "http://hl7.org/fhir/StructureDefinition/DocumentReference",
                        "interaction": [
                            {"code": "read"},
                            {"code": "search-type"},
                        ],
                        "searchParam": [
                            {"name": "_id", "type": "token"},
                            {"name": "patient", "type": "reference"},
                        ],
                    },
                ],
            }
        ],
    }


def create_operation_outcome(severity: str, code: str, diagnostics: str) -> dict:
    """Create FHIR OperationOutcome for errors"""
    return {
        "resourceType": "OperationOutcome",
        "id": f"outcome-{datetime.now().strftime('%Y%m%d%H%M%S')}",
        "issue": [
            {
                "severity": severity,
                "code": code,
                "diagnostics": diagnostics,
            }
        ],
    }


class FHIRHandler(BaseHTTPRequestHandler):
    """Handle FHIR REST API requests"""

    def log_message(self, format, *args):
        log.info(f"{self.client_address[0]} - {format % args}")

    def send_json_response(self, data: dict, status: int = 200):
        """Send JSON response with FHIR headers"""
        response = json.dumps(data, indent=2)
        self.send_response(status)
        self.send_header("Content-Type", "application/fhir+json; charset=utf-8")
        self.send_header("Content-Length", len(response))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("X-Powered-By", f"{SERVER_NAME}/{SERVER_VERSION}")
        self.end_headers()
        self.wfile.write(response.encode("utf-8"))

    def do_OPTIONS(self):
        """Handle CORS preflight"""
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.end_headers()

    def do_GET(self):
        """Handle GET requests"""
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")
        query_params = parse_qs(parsed.query)

        # Remove /fhir prefix if present
        if path.startswith("/fhir"):
            path = path[5:]

        log.info(f"GET {path} - Query: {query_params}")

        # Route to appropriate handler
        if path == "/metadata" or path == "":
            self.handle_capability_statement()
        elif path == "/.well-known/smart-configuration":
            self.handle_smart_configuration()
        elif path.startswith("/Patient"):
            self.handle_patient(path, query_params)
        elif path.startswith("/Observation"):
            self.handle_observation(path, query_params)
        elif path.startswith("/MedicationRequest"):
            self.handle_medication(path, query_params)
        elif path.startswith("/Condition"):
            self.handle_condition(path, query_params)
        elif path.startswith("/Encounter"):
            self.handle_encounter(path, query_params)
        elif path.startswith("/Procedure"):
            self.handle_procedure(path, query_params)
        elif path.startswith("/AllergyIntolerance"):
            self.handle_allergy(path, query_params)
        elif path.startswith("/Immunization"):
            self.handle_immunization(path, query_params)
        else:
            self.send_json_response(
                create_operation_outcome("error", "not-found", f"Unknown resource type: {path}"),
                404,
            )

    def handle_capability_statement(self):
        """Return CapabilityStatement"""
        self.send_json_response(create_capability_statement())

    def handle_smart_configuration(self):
        """Return SMART on FHIR configuration"""
        config = {
            "authorization_endpoint": f"{BASE_URL}/auth/authorize",
            "token_endpoint": f"{BASE_URL}/auth/token",
            "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
            "scopes_supported": [
                "openid",
                "profile",
                "launch",
                "launch/patient",
                "patient/*.read",
                "patient/*.write",
                "user/*.read",
                "user/*.write",
            ],
            "response_types_supported": ["code"],
            "capabilities": [
                "launch-ehr",
                "launch-standalone",
                "client-public",
                "client-confidential-symmetric",
                "context-ehr-patient",
                "context-standalone-patient",
                "permission-offline",
                "permission-patient",
                "permission-user",
            ],
        }
        self.send_json_response(config)

    def handle_patient(self, path: str, query_params: dict):
        """Handle Patient resource requests"""
        # Check for read by ID
        match = re.match(r"/Patient/([^/]+)$", path)
        if match:
            patient_id = match.group(1)
            for patient in MOCK_PATIENTS:
                if patient["id"] == patient_id:
                    self.send_json_response(create_resource("Patient", patient))
                    return
            self.send_json_response(
                create_operation_outcome("error", "not-found", f"Patient {patient_id} not found"),
                404,
            )
            return

        # Search
        results = []
        for patient in MOCK_PATIENTS:
            # Apply filters
            if "name" in query_params:
                name_filter = query_params["name"][0].lower()
                patient_name = patient["name"][0]["family"].lower()
                if name_filter not in patient_name:
                    continue

            if "gender" in query_params:
                if patient.get("gender") != query_params["gender"][0]:
                    continue

            if "_id" in query_params:
                if patient["id"] != query_params["_id"][0]:
                    continue

            results.append(create_resource("Patient", patient))

        # Apply _count limit
        max_results = int(query_params.get("_count", [100])[0])
        results = results[:max_results]

        self.send_json_response(create_bundle(results))

    def handle_observation(self, path: str, query_params: dict):
        """Handle Observation resource requests"""
        match = re.match(r"/Observation/([^/]+)$", path)
        if match:
            obs_id = match.group(1)
            for obs in MOCK_OBSERVATIONS:
                if obs["id"] == obs_id:
                    self.send_json_response(create_resource("Observation", obs))
                    return
            self.send_json_response(
                create_operation_outcome("error", "not-found", f"Observation {obs_id} not found"),
                404,
            )
            return

        results = []
        for obs in MOCK_OBSERVATIONS:
            if "patient" in query_params:
                patient_ref = query_params["patient"][0]
                if not patient_ref.startswith("Patient/"):
                    patient_ref = f"Patient/{patient_ref}"
                if obs["subject"]["reference"] != patient_ref:
                    continue

            if "category" in query_params:
                cat = query_params["category"][0]
                obs_cat = obs["category"][0]["coding"][0]["code"]
                if cat != obs_cat:
                    continue

            results.append(create_resource("Observation", obs))

        max_results = int(query_params.get("_count", [100])[0])
        results = results[:max_results]

        self.send_json_response(create_bundle(results))

    def handle_medication(self, path: str, query_params: dict):
        """Handle MedicationRequest resource requests"""
        match = re.match(r"/MedicationRequest/([^/]+)$", path)
        if match:
            med_id = match.group(1)
            for med in MOCK_MEDICATIONS:
                if med["id"] == med_id:
                    self.send_json_response(create_resource("MedicationRequest", med))
                    return
            self.send_json_response(
                create_operation_outcome(
                    "error", "not-found", f"MedicationRequest {med_id} not found"
                ),
                404,
            )
            return

        results = []
        for med in MOCK_MEDICATIONS:
            if "patient" in query_params:
                patient_ref = query_params["patient"][0]
                if not patient_ref.startswith("Patient/"):
                    patient_ref = f"Patient/{patient_ref}"
                if med["subject"]["reference"] != patient_ref:
                    continue

            results.append(create_resource("MedicationRequest", med))

        self.send_json_response(create_bundle(results))

    def handle_condition(self, path: str, query_params: dict):
        """Handle Condition resource requests"""
        match = re.match(r"/Condition/([^/]+)$", path)
        if match:
            con_id = match.group(1)
            for con in MOCK_CONDITIONS:
                if con["id"] == con_id:
                    self.send_json_response(create_resource("Condition", con))
                    return
            self.send_json_response(
                create_operation_outcome("error", "not-found", f"Condition {con_id} not found"),
                404,
            )
            return

        results = []
        for con in MOCK_CONDITIONS:
            if "patient" in query_params:
                patient_ref = query_params["patient"][0]
                if not patient_ref.startswith("Patient/"):
                    patient_ref = f"Patient/{patient_ref}"
                if con["subject"]["reference"] != patient_ref:
                    continue

            results.append(create_resource("Condition", con))

        self.send_json_response(create_bundle(results))

    def handle_encounter(self, path: str, query_params: dict):
        """Handle Encounter resource requests"""
        match = re.match(r"/Encounter/([^/]+)$", path)
        if match:
            enc_id = match.group(1)
            for enc in MOCK_ENCOUNTERS:
                if enc["id"] == enc_id:
                    self.send_json_response(create_resource("Encounter", enc))
                    return
            self.send_json_response(
                create_operation_outcome("error", "not-found", f"Encounter {enc_id} not found"),
                404,
            )
            return

        results = []
        for enc in MOCK_ENCOUNTERS:
            if "patient" in query_params:
                patient_ref = query_params["patient"][0]
                if not patient_ref.startswith("Patient/"):
                    patient_ref = f"Patient/{patient_ref}"
                if enc["subject"]["reference"] != patient_ref:
                    continue

            results.append(create_resource("Encounter", enc))

        self.send_json_response(create_bundle(results))

    def handle_procedure(self, path: str, query_params: dict):
        """Handle Procedure resource requests"""
        match = re.match(r"/Procedure/([^/]+)$", path)
        if match:
            proc_id = match.group(1)
            for proc in MOCK_PROCEDURES:
                if proc["id"] == proc_id:
                    self.send_json_response(create_resource("Procedure", proc))
                    return
            self.send_json_response(
                create_operation_outcome("error", "not-found", f"Procedure {proc_id} not found"),
                404,
            )
            return

        results = []
        for proc in MOCK_PROCEDURES:
            if "patient" in query_params:
                patient_ref = query_params["patient"][0]
                if not patient_ref.startswith("Patient/"):
                    patient_ref = f"Patient/{patient_ref}"
                if proc["subject"]["reference"] != patient_ref:
                    continue

            results.append(create_resource("Procedure", proc))

        self.send_json_response(create_bundle(results))

    def handle_allergy(self, path: str, query_params: dict):
        """Handle AllergyIntolerance resource requests"""
        match = re.match(r"/AllergyIntolerance/([^/]+)$", path)
        if match:
            all_id = match.group(1)
            for allergy in MOCK_ALLERGIES:
                if allergy["id"] == all_id:
                    self.send_json_response(create_resource("AllergyIntolerance", allergy))
                    return
            self.send_json_response(
                create_operation_outcome(
                    "error", "not-found", f"AllergyIntolerance {all_id} not found"
                ),
                404,
            )
            return

        results = []
        for allergy in MOCK_ALLERGIES:
            if "patient" in query_params:
                patient_ref = query_params["patient"][0]
                if not patient_ref.startswith("Patient/"):
                    patient_ref = f"Patient/{patient_ref}"
                if allergy["patient"]["reference"] != patient_ref:
                    continue

            results.append(create_resource("AllergyIntolerance", allergy))

        self.send_json_response(create_bundle(results))

    def handle_immunization(self, path: str, query_params: dict):
        """Handle Immunization resource requests"""
        match = re.match(r"/Immunization/([^/]+)$", path)
        if match:
            imm_id = match.group(1)
            for imm in MOCK_IMMUNIZATIONS:
                if imm["id"] == imm_id:
                    self.send_json_response(create_resource("Immunization", imm))
                    return
            self.send_json_response(
                create_operation_outcome("error", "not-found", f"Immunization {imm_id} not found"),
                404,
            )
            return

        results = []
        for imm in MOCK_IMMUNIZATIONS:
            if "patient" in query_params:
                patient_ref = query_params["patient"][0]
                if not patient_ref.startswith("Patient/"):
                    patient_ref = f"Patient/{patient_ref}"
                if imm["patient"]["reference"] != patient_ref:
                    continue

            results.append(create_resource("Immunization", imm))

        self.send_json_response(create_bundle(results))


def main():
    """Start the mock FHIR server"""
    host = "0.0.0.0"
    port = 8080

    log.info(f"Starting {SERVER_NAME} v{SERVER_VERSION}")
    log.info(f"FHIR Version: {FHIR_VERSION}")
    log.info(f"Listening on {host}:{port}")
    log.info(f"Base URL: {BASE_URL}")

    # Log mock data stats
    log.info("Mock database contents:")
    log.info(f"  - Patients: {len(MOCK_PATIENTS)}")
    log.info(f"  - Observations: {len(MOCK_OBSERVATIONS)}")
    log.info(f"  - MedicationRequests: {len(MOCK_MEDICATIONS)}")
    log.info(f"  - Conditions: {len(MOCK_CONDITIONS)}")
    log.info(f"  - Encounters: {len(MOCK_ENCOUNTERS)}")
    log.info(f"  - Procedures: {len(MOCK_PROCEDURES)}")
    log.info(f"  - AllergyIntolerances: {len(MOCK_ALLERGIES)}")
    log.info(f"  - Immunizations: {len(MOCK_IMMUNIZATIONS)}")

    server = HTTPServer((host, port), FHIRHandler)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        log.info("Server shutting down")
        server.shutdown()


if __name__ == "__main__":
    main()
