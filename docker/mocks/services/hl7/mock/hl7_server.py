#!/usr/bin/env python3
"""
Mock HL7 v2 MLLP Server for testing OIDA HL7 scanner

Built on hl7apy's MLLPServer with per-message-type handler routing.

Features:
- Per-message-type handlers (ADT, QRY, ORM, ORU, SIU, MDM, MFN, QBP,
  BAR, DFT, RDE, RAS, RGV, RDS, PCD/ORU^R01, MFQ, VXU)
- TLS/MLLPS support (env var configurable, auto-generates self-signed certs)
- Configurable response modes: normal, error, reject, random
- NAK responses for malformed/unsupported messages

Supports enumeration testing:
- Provider enumeration (--enum-providers): PV1-7/8/9/17, OBR-16
- Location enumeration (--enum-locations): PV1-3
- Application enumeration (--enum-apps): MSH-3/4 variations

Environment variables:
- ENABLE_TLS: "1" to enable TLS (default: disabled)
- TLS_CERT, TLS_KEY, TLS_CA: paths to certificate files
- RESPONSE_MODE: "normal" (default), "error", "reject", "random"
- HL7_PORT: listen port (default: 2575)
- HL7_TLS_PORT: TLS listen port (default: 2576)
"""

import logging
import os
import random
import re
import socket
import ssl
import subprocess
import tempfile
import threading
from datetime import datetime

try:
    from socketserver import StreamRequestHandler, ThreadingTCPServer
except ImportError:
    from SocketServer import StreamRequestHandler, ThreadingTCPServer

from hl7apy.mllp import (
    AbstractErrorHandler,
    AbstractHandler,
    InvalidHL7Message,
    MLLPServer,
    UnsupportedMessageType,
)
from hl7apy.parser import get_message_type

logging.basicConfig(level=logging.INFO)
log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Server configuration
# ---------------------------------------------------------------------------
SERVER_APP = "MOCK_HIS"
SERVER_FACILITY = "MAIN_HOSPITAL"
HL7_VERSION = "2.5"

RESPONSE_MODE = os.environ.get("RESPONSE_MODE", "normal").lower()

# ---------------------------------------------------------------------------
# Mock data (preserved from original)
# ---------------------------------------------------------------------------

MOCK_APPS = [
    ("EPIC", "MAIN_HOSPITAL"),
    ("EPIC", "EAST_CAMPUS"),
    ("CERNER", "CLINIC_WEST"),
    ("MEDITECH", "SATELLITE_CLINIC"),
    ("MIRTH", "INTERFACE_ENGINE"),
    ("RHAPSODY", "HIE_GATEWAY"),
    ("ALLSCRIPTS", "AMBULATORY"),
    ("NEXTGEN", "URGENT_CARE"),
]

MOCK_PROVIDERS = [
    {"id": "1234567890", "name": "ATTENDING^DOCTOR^JAMES^MD", "role": "ATTENDING"},
    {"id": "2345678901", "name": "REFERRING^PHYSICIAN^MARY^MD", "role": "REFERRING"},
    {"id": "3456789012", "name": "CONSULTING^SPECIALIST^ROBERT^MD", "role": "CONSULTING"},
    {"id": "4567890123", "name": "ADMITTING^DOCTOR^SUSAN^MD", "role": "ADMITTING"},
    {"id": "5678901234", "name": "ORDERING^PROVIDER^LISA^MD", "role": "ORDERING"},
    {"id": "6789012345", "name": "PRIMARY^CARE^JOHN^MD", "role": "PRIMARY"},
    {"id": "7890123456", "name": "SURGEON^CARDIAC^PETER^MD", "role": "SURGEON"},
    {"id": "8901234567", "name": "ONCOLOGIST^KAREN^MD", "role": "ONCOLOGIST"},
]

MOCK_LOCATIONS = [
    "ICU^101^A^MAIN_HOSPITAL^^^^^N",
    "ICU^102^B^MAIN_HOSPITAL^^^^^N",
    "ICU^103^C^MAIN_HOSPITAL^^^^^N",
    "ER^001^1^EMERGENCY^^^^^N",
    "ER^002^2^EMERGENCY^^^^^N",
    "ER^TRAUMA-1^^EMERGENCY^^^^^N",
    "SURGERY^OR-1^^SURGICAL_CENTER^^^^^N",
    "SURGERY^OR-2^^SURGICAL_CENTER^^^^^N",
    "SURGERY^PACU-1^A^SURGICAL_CENTER^^^^^N",
    "PEDS^201^A^CHILDRENS_WING^^^^^N",
    "PEDS^202^B^CHILDRENS_WING^^^^^N",
    "MED-SURG^305^B^MAIN_HOSPITAL^^^^^N",
    "MED-SURG^306^A^MAIN_HOSPITAL^^^^^N",
    "MED-SURG^307^C^MAIN_HOSPITAL^^^^^N",
    "ONCOLOGY^401^A^CANCER_CENTER^^^^^N",
    "ONCOLOGY^402^B^CANCER_CENTER^^^^^N",
    "CARDIAC^501^A^HEART_CENTER^^^^^N",
    "CARDIAC^CCU-1^A^HEART_CENTER^^^^^N",
    "NEURO^601^A^MAIN_HOSPITAL^^^^^N",
    "PSYCH^701^A^BEHAVIORAL_HEALTH^^^^^N",
]

MOCK_PATIENTS = [
    {
        "id": "PT001",
        "name": "DOE^JOHN^MICHAEL",
        "dob": "19800101",
        "sex": "M",
        "ssn": "123-45-6789",
        "address": "123 MAIN ST^^ANYTOWN^ST^12345^USA",
        "phone": "(555)123-4567",
    },
    {
        "id": "PT002",
        "name": "SMITH^JANE^ANN",
        "dob": "19750515",
        "sex": "F",
        "ssn": "234-56-7890",
        "address": "456 OAK AVE^^SOMEWHERE^ST^23456^USA",
        "phone": "(555)234-5678",
    },
    {
        "id": "PT003",
        "name": "JOHNSON^ROBERT^LEE",
        "dob": "19650320",
        "sex": "M",
        "ssn": "345-67-8901",
        "address": "789 ELM ST^^NOWHERE^ST^34567^USA",
        "phone": "(555)345-6789",
    },
    {
        "id": "PT004",
        "name": "WILLIAMS^MARY^KATE",
        "dob": "19900710",
        "sex": "F",
        "ssn": "456-78-9012",
        "address": "321 PINE RD^^ELSEWHERE^ST^45678^USA",
        "phone": "(555)456-7890",
    },
    {
        "id": "PT005",
        "name": "BROWN^DAVID^JAMES",
        "dob": "19551230",
        "sex": "M",
        "ssn": "567-89-0123",
        "address": "654 MAPLE DR^^ANYWHERE^ST^56789^USA",
        "phone": "(555)567-8901",
    },
]

# Mock medications for pharmacy responses
MOCK_MEDICATIONS = [
    {
        "code": "00069-3150-83",
        "name": "AMOXICILLIN 500MG",
        "dose": "500",
        "units": "mg",
        "route": "PO",
        "frequency": "TID",
    },
    {
        "code": "00069-0150-01",
        "name": "LISINOPRIL 10MG",
        "dose": "10",
        "units": "mg",
        "route": "PO",
        "frequency": "QD",
    },
    {
        "code": "00002-8215-01",
        "name": "INSULIN LISPRO",
        "dose": "10",
        "units": "units",
        "route": "SC",
        "frequency": "AC",
    },
    {
        "code": "00173-0521-00",
        "name": "MORPHINE SULFATE 4MG",
        "dose": "4",
        "units": "mg",
        "route": "IV",
        "frequency": "Q4H PRN",
    },
    {
        "code": "59762-3314-01",
        "name": "METFORMIN 500MG",
        "dose": "500",
        "units": "mg",
        "route": "PO",
        "frequency": "BID",
    },
]

# Mock immunizations for QBP^Z34/Z44 responses
MOCK_IMMUNIZATIONS = [
    {"code": "08", "name": "HEPATITIS B", "date": "19800215", "lot": "LOT2024A", "mfr": "MERCK"},
    {"code": "20", "name": "DTaP", "date": "19800601", "lot": "LOT2024B", "mfr": "SANOFI"},
    {"code": "10", "name": "IPV", "date": "19800601", "lot": "LOT2024C", "mfr": "SANOFI"},
    {"code": "03", "name": "MMR", "date": "19810701", "lot": "LOT2024D", "mfr": "MERCK"},
    {"code": "21", "name": "VARICELLA", "date": "19810701", "lot": "LOT2024E", "mfr": "MERCK"},
    {"code": "33", "name": "PNEUMOCOCCAL", "date": "19800601", "lot": "LOT2024F", "mfr": "PFIZER"},
    {"code": "141", "name": "COVID-19 mRNA", "date": "20210415", "lot": "EW0167", "mfr": "PFIZER"},
]

# Mock staff for MFN^M02 responses
MOCK_STAFF = [
    {
        "id": "STF001",
        "name": "SMITH^JOHN^MD",
        "type": "MD",
        "dept": "CARDIOLOGY",
        "phone": "(555)100-0001",
        "status": "A",
    },
    {
        "id": "STF002",
        "name": "JONES^MARY^RN",
        "type": "RN",
        "dept": "ICU",
        "phone": "(555)100-0002",
        "status": "A",
    },
    {
        "id": "STF003",
        "name": "WILLIAMS^ROBERT^MD",
        "type": "MD",
        "dept": "SURGERY",
        "phone": "(555)100-0003",
        "status": "A",
    },
    {
        "id": "STF004",
        "name": "BROWN^SARAH^NP",
        "type": "NP",
        "dept": "EMERGENCY",
        "phone": "(555)100-0004",
        "status": "A",
    },
    {
        "id": "STF005",
        "name": "DAVIS^MICHAEL^PA",
        "type": "PA",
        "dept": "ORTHOPEDICS",
        "phone": "(555)100-0005",
        "status": "I",
    },
]

# Mock charge codes for MFN^M04 responses
MOCK_CHARGES = [
    {"code": "99213", "desc": "Office Visit Level 3", "price": "150.00", "dept": "AMBULATORY"},
    {"code": "99214", "desc": "Office Visit Level 4", "price": "250.00", "dept": "AMBULATORY"},
    {"code": "36415", "desc": "Venipuncture", "price": "25.00", "dept": "LAB"},
    {"code": "85025", "desc": "CBC with Differential", "price": "45.00", "dept": "LAB"},
    {"code": "80053", "desc": "Comprehensive Metabolic Panel", "price": "65.00", "dept": "LAB"},
    {"code": "71046", "desc": "Chest X-Ray 2 Views", "price": "175.00", "dept": "RADIOLOGY"},
]

# Mock scheduling slots for SIU responses
MOCK_SCHEDULES = [
    {
        "appt_id": "APT001",
        "type": "FOLLOWUP",
        "provider": "SMITH^JOHN^MD",
        "location": "CLINIC_A^201^^AMBULATORY",
        "duration": "30",
    },
    {
        "appt_id": "APT002",
        "type": "NEW_PATIENT",
        "provider": "JONES^MARY^NP",
        "location": "CLINIC_B^102^^AMBULATORY",
        "duration": "60",
    },
    {
        "appt_id": "APT003",
        "type": "PROCEDURE",
        "provider": "WILLIAMS^ROBERT^MD",
        "location": "SURGERY^OR-1^^SURGICAL_CENTER",
        "duration": "120",
    },
]

# Mock documents for MDM responses
MOCK_DOCUMENTS = [
    {
        "id": "DOC001",
        "type": "HP",
        "title": "History and Physical",
        "author": "SMITH^JOHN^MD",
        "status": "AU",
    },
    {
        "id": "DOC002",
        "type": "DS",
        "title": "Discharge Summary",
        "author": "ATTENDING^DOCTOR^JAMES^MD",
        "status": "AU",
    },
    {
        "id": "DOC003",
        "type": "OP",
        "title": "Operative Report",
        "author": "SURGEON^CARDIAC^PETER^MD",
        "status": "DI",
    },
    {
        "id": "DOC004",
        "type": "CN",
        "title": "Consultation Note",
        "author": "CONSULTING^SPECIALIST^ROBERT^MD",
        "status": "AU",
    },
]


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _now() -> str:
    return datetime.now().strftime("%Y%m%d%H%M%S")


def _msg_id() -> str:
    return f"MSG{_now()}"


def _ack_code() -> str:
    """Return ACK code based on RESPONSE_MODE."""
    if RESPONSE_MODE == "error":
        return "AE"
    elif RESPONSE_MODE == "reject":
        return "AR"
    elif RESPONSE_MODE == "random":
        return random.choice(["AA", "AE", "AR"])
    return "AA"


def _random_app_facility() -> tuple:
    return random.choice(MOCK_APPS)


def _provider(role: str) -> dict:
    return next((p for p in MOCK_PROVIDERS if p["role"] == role), MOCK_PROVIDERS[0])


def _parse_msh(message: str) -> dict:
    """Parse MSH fields from raw ER7 message string."""
    info = {}
    for line in message.split("\r"):
        if not line.startswith("MSH"):
            continue
        sep = line[3] if len(line) > 3 else "|"
        fields = line.split(sep)
        if len(fields) > 2:
            info["sending_app"] = fields[2]
        if len(fields) > 3:
            info["sending_facility"] = fields[3]
        if len(fields) > 4:
            info["receiving_app"] = fields[4]
        if len(fields) > 5:
            info["receiving_facility"] = fields[5]
        if len(fields) > 8:
            info["message_type"] = fields[8]
        if len(fields) > 9:
            info["message_control_id"] = fields[9]
        if len(fields) > 11:
            info["version"] = fields[11]
        break
    return info


def _msh_header(msh_info: dict, msg_type: str) -> str:
    app, facility = _random_app_facility()
    version = msh_info.get("version", HL7_VERSION)
    return (
        f"MSH|^~\\&|{app}|{facility}|"
        f"{msh_info.get('sending_app', 'UNKNOWN')}|"
        f"{msh_info.get('sending_facility', 'UNKNOWN')}|"
        f"{_now()}||{msg_type}|{_msg_id()}|P|{version}"
    )


def _pid_segment(patient: dict = None) -> str:
    if patient is None:
        patient = random.choice(MOCK_PATIENTS)
    return (
        f"PID|1||{patient['id']}^^^HOSP^MR~{patient['ssn']}^^^USSSA^SS||"
        f"{patient['name']}||{patient['dob']}|{patient['sex']}|||"
        f"{patient['address']}||{patient['phone']}|||||||||||||||||||||"
    )


def _pv1_segment(location: str = None) -> str:
    if location is None:
        location = random.choice(MOCK_LOCATIONS)
    attending = _provider("ATTENDING")
    referring = _provider("REFERRING")
    consulting = _provider("CONSULTING")
    admitting = _provider("ADMITTING")
    return (
        f"PV1|1|I|{location}||||"
        f"{attending['name']}^{attending['id']}^^^^^NPI|"
        f"{referring['name']}^{referring['id']}^^^^^NPI|"
        f"{consulting['name']}^{consulting['id']}^^^^^NPI|"
        f"||||||||"
        f"{admitting['name']}^{admitting['id']}^^^^^NPI|"
        f"||||||||||||||||||||||||||"
        f"{_now()}|"
    )


def _obr_segment(order_id: str = None) -> str:
    if order_id is None:
        order_id = f"ORD{_now()}"
    ordering = _provider("ORDERING")
    return (
        f"OBR|1|{order_id}||CBC^Complete Blood Count^L|||{_now()}||||||||"
        f"BLOOD^VENOUS|"
        f"{ordering['name']}^{ordering['id']}^^^^^NPI|"
        f"|(555)999-8888|||||||||||||||||||||||"
    )


def _rich_ack_segments(msh_info: dict) -> list:
    """Common ACK + NTE segments appended to most responses."""
    return [
        "ERR|0|MSH^1^1|0|I|0|SUCCESS|||Contact IT at helpdesk@hospital.local",
        f"NTE|1|L|Server: {SERVER_APP} v{HL7_VERSION} at {SERVER_FACILITY}",
        "NTE|2|L|Interface Engine: Mirth Connect 4.5.0",
    ]


# ---------------------------------------------------------------------------
# Handler base class
# ---------------------------------------------------------------------------


class BaseHL7Handler(AbstractHandler):
    """Base handler that parses MSH and applies response-mode logic."""

    def __init__(self, message):
        super().__init__(message)
        self.msh_info = _parse_msh(message)

    def reply(self):
        """Generate response. Subclasses override _build_response()."""
        log.info(
            "  Message Type: %s  From: %s/%s",
            self.msh_info.get("message_type", "?"),
            self.msh_info.get("sending_app", "?"),
            self.msh_info.get("sending_facility", "?"),
        )
        return self._build_response()

    def _build_response(self) -> str:
        """Override in subclasses to produce specific responses."""
        return self._generic_ack()

    # -- Shared response builders -------------------------------------------

    def _generic_ack(self, msg_type_override: str = None) -> str:
        """Build a generic ACK with rich context segments."""
        mt = self.msh_info.get("message_type", "")
        ack_type = msg_type_override or (mt.split("^")[0] if "^" in mt else "ACK")
        msg_control_id = self.msh_info.get("message_control_id", "UNKNOWN")

        lines = [
            _msh_header(self.msh_info, f"ACK^{ack_type}"),
            f"MSA|{_ack_code()}|{msg_control_id}|Message accepted",
        ]
        lines.extend(_rich_ack_segments(self.msh_info))
        return "\r".join(lines) + "\r"


# ---------------------------------------------------------------------------
# Message-type handlers
# ---------------------------------------------------------------------------


class ADTHandler(BaseHL7Handler):
    """Handle ADT (Admit/Discharge/Transfer) messages."""

    def _build_response(self) -> str:
        mt = self.msh_info.get("message_type", "ADT^A01")
        trigger = mt.split("^")[1] if "^" in mt else "A01"
        msg_control_id = self.msh_info.get("message_control_id", "UNKNOWN")

        lines = [_msh_header(self.msh_info, f"ACK^{trigger}")]
        lines.append(f"MSA|{_ack_code()}|{msg_control_id}|Message accepted")
        lines.append(f"EVN|{trigger}|{_now()}|||REGISTRATION^SYSTEM")

        patient = random.choice(MOCK_PATIENTS)
        lines.append(_pid_segment(patient))
        lines.append(_pv1_segment())
        lines.append("DG1|1|I10|J18.9^Pneumonia, unspecified organism^I10|||A|||||||||1")
        return "\r".join(lines) + "\r"


class QRYHandler(BaseHL7Handler):
    """Handle QRY (Query) messages - return patient data."""

    def _build_response(self) -> str:
        msg_control_id = self.msh_info.get("message_control_id", "UNKNOWN")

        lines = [_msh_header(self.msh_info, "RSP^K11^RSP_K11")]
        lines.append(f"MSA|{_ack_code()}|{msg_control_id}|Query successful")
        lines.append("QAK|1|OK|Q22^Find Candidates^HL70471")
        lines.append("QPD|Q22^Find Candidates^HL70471|Q001|@PID.5.1^*")

        for i, patient in enumerate(MOCK_PATIENTS[:3]):
            lines.append(_pid_segment(patient))
            lines.append(_pv1_segment(MOCK_LOCATIONS[i % len(MOCK_LOCATIONS)]))

        return "\r".join(lines) + "\r"


class ORMHandler(BaseHL7Handler):
    """Handle ORM (Order) messages."""

    def _build_response(self) -> str:
        mt = self.msh_info.get("message_type", "ORM^O01")
        trigger = mt.split("^")[1] if "^" in mt else "O02"
        msg_control_id = self.msh_info.get("message_control_id", "UNKNOWN")

        lines = [_msh_header(self.msh_info, f"ORR^{trigger}")]
        lines.append(f"MSA|{_ack_code()}|{msg_control_id}|Order accepted")

        patient = random.choice(MOCK_PATIENTS)
        lines.append(_pid_segment(patient))
        lines.append(_pv1_segment())

        ordering = _provider("ORDERING")
        lines.append(
            f"ORC|OK|ORD{_now()}||GRP001|||^^^{_now()}^^R||{_now()}|"
            f"{ordering['name']}^{ordering['id']}^^^^^NPI|"
            f"|||||||||"
        )
        lines.append(_obr_segment())

        lines.append("OBX|1|NM|WBC^White Blood Cell Count^L||7.5|10*3/uL|4.5-11.0|N|||F")
        lines.append("OBX|2|NM|RBC^Red Blood Cell Count^L||4.8|10*6/uL|4.5-5.5|N|||F")
        lines.append("OBX|3|NM|HGB^Hemoglobin^L||14.2|g/dL|12.0-16.0|N|||F")
        return "\r".join(lines) + "\r"


class ORUHandler(BaseHL7Handler):
    """Handle ORU (Observation Result) messages, including PCD-01 device obs."""

    def _build_response(self) -> str:
        msg_control_id = self.msh_info.get("message_control_id", "UNKNOWN")

        lines = [_msh_header(self.msh_info, "ACK^R01")]
        lines.append(f"MSA|{_ack_code()}|{msg_control_id}|Observation accepted")

        patient = random.choice(MOCK_PATIENTS)
        lines.append(_pid_segment(patient))
        lines.append(_pv1_segment())

        # Echo back some observations
        lines.append("OBX|1|NM|WBC^White Blood Cell Count^L||7.5|10*3/uL|4.5-11.0|N|||F")
        lines.append("OBX|2|NM|RBC^Red Blood Cell Count^L||4.8|10*6/uL|4.5-5.5|N|||F")
        lines.append("OBX|3|NM|HGB^Hemoglobin^L||14.2|g/dL|12.0-16.0|N|||F")
        lines.append("OBX|4|NM|PLT^Platelet Count^L||250|10*3/uL|150-400|N|||F")
        return "\r".join(lines) + "\r"


class SIUHandler(BaseHL7Handler):
    """Handle SIU (Scheduling) messages."""

    def _build_response(self) -> str:
        mt = self.msh_info.get("message_type", "SIU^S12")
        trigger = mt.split("^")[1] if "^" in mt else "S12"
        msg_control_id = self.msh_info.get("message_control_id", "UNKNOWN")

        lines = [_msh_header(self.msh_info, f"ACK^{trigger}")]
        lines.append(f"MSA|{_ack_code()}|{msg_control_id}|Schedule updated")

        patient = random.choice(MOCK_PATIENTS)
        lines.append(_pid_segment(patient))
        lines.append(_pv1_segment())

        sched = random.choice(MOCK_SCHEDULES)
        now = _now()
        lines.append(
            f"SCH|{sched['appt_id']}||||||"
            f"{sched['type']}^{sched['type']}^HL70277|{sched['duration']}|min|"
            f"^^^{now}^^R||"
            f"{sched['provider']}^^^^^NPI|"
            f"||{sched['location']}"
        )
        lines.append(
            f"AIS|1|{sched['appt_id']}|99213^Office Visit^CPT|{now}|{sched['duration']}|min"
        )

        return "\r".join(lines) + "\r"


class MDMHandler(BaseHL7Handler):
    """Handle MDM (Document) messages."""

    def _build_response(self) -> str:
        mt = self.msh_info.get("message_type", "MDM^T02")
        trigger = mt.split("^")[1] if "^" in mt else "T02"
        msg_control_id = self.msh_info.get("message_control_id", "UNKNOWN")

        lines = [_msh_header(self.msh_info, f"ACK^{trigger}")]
        lines.append(f"MSA|{_ack_code()}|{msg_control_id}|Document received")

        patient = random.choice(MOCK_PATIENTS)
        lines.append(_pid_segment(patient))
        lines.append(_pv1_segment())

        doc = random.choice(MOCK_DOCUMENTS)
        lines.append(
            f"TXA|1|{doc['type']}|TX|{_now()}|{doc['author']}^^^^^NPI|"
            f"||||||{doc['id']}||||{doc['status']}||"
        )
        lines.append(
            f"OBX|1|TX|{doc['type']}^{doc['title']}||"
            f"This is mock document content for {doc['title']}.||||||F"
        )

        return "\r".join(lines) + "\r"


class MFNHandler(BaseHL7Handler):
    """Handle MFN (Master File Notification) messages."""

    def _build_response(self) -> str:
        mt = self.msh_info.get("message_type", "MFN^M01")
        trigger = mt.split("^")[1] if "^" in mt else "M01"
        msg_control_id = self.msh_info.get("message_control_id", "UNKNOWN")

        lines = [_msh_header(self.msh_info, f"MFK^{trigger}")]
        lines.append(f"MSA|{_ack_code()}|{msg_control_id}|Master file update acknowledged")
        lines.append(f"MFI|{trigger}^Master File^HL70175||UPD|{_now()}||AL")

        if trigger == "M02":
            # Staff master file response
            for staff in MOCK_STAFF[:3]:
                lines.append(f"MFE|MAD|MFE{_now()}|{_now()}|{staff['id']}")
                lines.append(
                    f"STF|{staff['id']}||{staff['name']}|{staff['type']}||||"
                    f"{staff['dept']}||{staff['phone']}|||||"
                )
        elif trigger == "M04":
            # Charge master file response
            for charge in MOCK_CHARGES[:3]:
                lines.append(f"MFE|MAD|MFE{_now()}|{_now()}|{charge['code']}")
                lines.append(
                    f"PRC|{charge['code']}^{charge['desc']}^CPT|MAIN_HOSPITAL|"
                    f"{charge['dept']}||{charge['price']}|||||{_now()}|"
                )
        else:
            # Generic master file
            lines.append(f"MFE|MAD|MFE{_now()}|{_now()}|TEST001")

        return "\r".join(lines) + "\r"


class MFQHandler(BaseHL7Handler):
    """Handle MFQ (Master File Query) messages."""

    def _build_response(self) -> str:
        msg_control_id = self.msh_info.get("message_control_id", "UNKNOWN")

        lines = [_msh_header(self.msh_info, "MFR^M01")]
        lines.append(f"MSA|{_ack_code()}|{msg_control_id}|Master file query response")
        lines.append(f"MFI|STF^Staff Master File^HL70175||UPD|{_now()}||AL")

        # Return all staff entries
        for staff in MOCK_STAFF:
            lines.append(f"MFE|MAD|MFE{_now()}|{_now()}|{staff['id']}")
            lines.append(
                f"STF|{staff['id']}||{staff['name']}|{staff['type']}||||"
                f"{staff['dept']}||{staff['phone']}|||||"
            )

        # Also return charge entries
        lines.append(f"MFI|CDM^Charge Description Master^HL70175||UPD|{_now()}||AL")
        for charge in MOCK_CHARGES:
            lines.append(f"MFE|MAD|MFE{_now()}|{_now()}|{charge['code']}")
            lines.append(
                f"PRC|{charge['code']}^{charge['desc']}^CPT|MAIN_HOSPITAL|"
                f"{charge['dept']}||{charge['price']}|||||{_now()}|"
            )

        return "\r".join(lines) + "\r"


class QBPHandler(BaseHL7Handler):
    """Handle QBP (Query By Parameter) messages."""

    def _build_response(self) -> str:
        mt = self.msh_info.get("message_type", "QBP^Q13")
        trigger = mt.split("^")[1] if "^" in mt else "Q13"
        msg_control_id = self.msh_info.get("message_control_id", "UNKNOWN")

        if trigger == "Q40":
            return self._whoami_response(msg_control_id)
        elif trigger == "Q13":
            return self._tabular_response(msg_control_id)
        elif trigger in ("Z34", "Z44"):
            return self._immunization_response(msg_control_id, trigger)
        else:
            return self._generic_qbp_response(msg_control_id, trigger)

    def _whoami_response(self, msg_control_id: str) -> str:
        lines = [_msh_header(self.msh_info, "RSP^Q40^RSP_K11")]
        lines.append(f"MSA|{_ack_code()}|{msg_control_id}|WhoAmI query response")
        lines.append("QAK|1|OK|Q40^WhoAmI^HL70471")
        lines.append("QPD|Q40^WhoAmI^HL70471|Q001|")
        lines.append(f"NTE|1|L|Server: {SERVER_APP} v{HL7_VERSION}")
        lines.append(f"NTE|2|L|Facility: {SERVER_FACILITY}")
        lines.append("NTE|3|L|Supported: ADT,ORM,ORU,QRY,SIU,MDM,MFN,QBP,BAR,DFT,RDE,RAS,RGV,RDS")
        lines.append("NTE|4|L|Interface Engine: Mirth Connect 4.5.0")
        lines.append("NTE|5|L|Database: PostgreSQL 15.3")
        return "\r".join(lines) + "\r"

    def _tabular_response(self, msg_control_id: str) -> str:
        lines = [_msh_header(self.msh_info, "RTB^K13^RTB_K13")]
        lines.append(f"MSA|{_ack_code()}|{msg_control_id}|Tabular query response")
        lines.append("QAK|1|OK|Q13^TabularPatientList^HL70471")
        lines.append("QPD|Q13^TabularPatientList^HL70471|Q001|@PID.5.1^*")
        # RDF - column definitions
        lines.append("RDF|5|PatientID^ST~PatientName^ST~DOB^DT~Sex^ST~Phone^ST")
        # RDT - data rows
        for p in MOCK_PATIENTS:
            lines.append(f"RDT|{p['id']}~{p['name']}~{p['dob']}~{p['sex']}~{p['phone']}")
        return "\r".join(lines) + "\r"

    def _immunization_response(self, msg_control_id: str, trigger: str) -> str:
        resp_trigger = "Z32" if trigger == "Z34" else "Z42"
        lines = [_msh_header(self.msh_info, f"RSP^{resp_trigger}^RSP_K11")]
        lines.append(f"MSA|{_ack_code()}|{msg_control_id}|Immunization query response")
        lines.append(f"QAK|1|OK|{trigger}^Request Immunization History^CDCPHINVS")

        patient = random.choice(MOCK_PATIENTS)
        lines.append(_pid_segment(patient))

        for i, imm in enumerate(MOCK_IMMUNIZATIONS):
            lines.append(
                f"RXA|0|{i + 1}|{imm['date']}||"
                f"{imm['code']}^{imm['name']}^CVX|1|mL|||||"
                f"||{imm['lot']}||{imm['mfr']}||||CP"
            )

        if trigger == "Z44":
            # Forecast data
            lines.append(
                f"RXA|0|{len(MOCK_IMMUNIZATIONS) + 1}|{_now()}||"
                "88^INFLUENZA^CVX|999|||||||||||FORECAST||||RE"
            )
            lines.append("OBX|1|CE|30956-7^Vaccine Type^LN||88^INFLUENZA^CVX||||||F")
            lines.append(f"OBX|2|DT|30981-5^Earliest Date^LN||{_now()}||||||F")

        return "\r".join(lines) + "\r"

    def _generic_qbp_response(self, msg_control_id: str, trigger: str) -> str:
        lines = [_msh_header(self.msh_info, f"RSP^{trigger}^RSP_K11")]
        lines.append(f"MSA|{_ack_code()}|{msg_control_id}|Query response")
        lines.append(f"QAK|1|OK|{trigger}^Query^HL70471")
        for i, patient in enumerate(MOCK_PATIENTS[:3]):
            lines.append(_pid_segment(patient))
            lines.append(_pv1_segment(MOCK_LOCATIONS[i % len(MOCK_LOCATIONS)]))
        return "\r".join(lines) + "\r"


class BARHandler(BaseHL7Handler):
    """Handle BAR (Billing/Account) messages."""

    def _build_response(self) -> str:
        msg_control_id = self.msh_info.get("message_control_id", "UNKNOWN")

        lines = [_msh_header(self.msh_info, "ACK^P01")]
        lines.append(f"MSA|{_ack_code()}|{msg_control_id}|Billing account accepted")

        patient = random.choice(MOCK_PATIENTS)
        lines.append(_pid_segment(patient))
        lines.append(_pv1_segment())

        # GT1 - Guarantor
        lines.append(
            f"GT1|1|GT{_now()}|{patient['name']}||"
            f"{patient['address']}|{patient['phone']}|||||||"
            f"{patient['ssn']}|||SELF^Self^HL70063"
        )

        # IN1 - Insurance
        lines.append(
            f"IN1|1|BCBS001^Blue Cross Blue Shield^HL70072|INS001|"
            f"Blue Cross Blue Shield|123 INSURANCE BLVD^^PAYTOWN^ST^99999||||"
            f"GRP001|||{_now()}||||{patient['name']}|||||||||||"
            f"POL{_now()}"
        )

        # FT1 - Financial Transaction
        lines.append(
            f"FT1|1|BATCH001||{_now()}|{_now()}|CG|99213^Office Visit Level 3^CPT|"
            f"Office Visit|1|150.00||||{patient['id']}|||"
        )

        return "\r".join(lines) + "\r"


class DFTHandler(BaseHL7Handler):
    """Handle DFT (Financial Transaction) messages."""

    def _build_response(self) -> str:
        msg_control_id = self.msh_info.get("message_control_id", "UNKNOWN")

        lines = [_msh_header(self.msh_info, "ACK^P03")]
        lines.append(f"MSA|{_ack_code()}|{msg_control_id}|Financial transaction posted")

        patient = random.choice(MOCK_PATIENTS)
        lines.append(_pid_segment(patient))
        lines.append(_pv1_segment())

        # FT1 - Financial transactions
        for i, charge in enumerate(MOCK_CHARGES[:3]):
            lines.append(
                f"FT1|{i + 1}|BATCH001||{_now()}|{_now()}|CG|"
                f"{charge['code']}^{charge['desc']}^CPT|{charge['desc']}|1|"
                f"{charge['price']}||||{patient['id']}|||"
            )

        return "\r".join(lines) + "\r"


class RDEHandler(BaseHL7Handler):
    """Handle RDE (Pharmacy Encoded Order) messages."""

    def _build_response(self) -> str:
        msg_control_id = self.msh_info.get("message_control_id", "UNKNOWN")

        lines = [_msh_header(self.msh_info, "RRE^O12")]
        lines.append(f"MSA|{_ack_code()}|{msg_control_id}|Pharmacy order accepted")

        patient = random.choice(MOCK_PATIENTS)
        lines.append(_pid_segment(patient))
        lines.append(_pv1_segment())

        med = random.choice(MOCK_MEDICATIONS)
        ordering = _provider("ORDERING")
        lines.append(
            f"ORC|OK|RX{_now()}||GRP001|||^^^{_now()}^^R||{_now()}|"
            f"{ordering['name']}^{ordering['id']}^^^^^NPI||||||||||"
        )
        lines.append(
            f"RXE|1|{med['code']}^{med['name']}^NDC|{med['dose']}||"
            f"{med['units']}|{med['route']}||||30|{med['units']}|||RX{_now()}|0"
        )

        return "\r".join(lines) + "\r"


class RASHandler(BaseHL7Handler):
    """Handle RAS (Pharmacy Administration) messages."""

    def _build_response(self) -> str:
        msg_control_id = self.msh_info.get("message_control_id", "UNKNOWN")

        lines = [_msh_header(self.msh_info, "ACK^O17")]
        lines.append(f"MSA|{_ack_code()}|{msg_control_id}|Administration recorded")

        patient = random.choice(MOCK_PATIENTS)
        lines.append(_pid_segment(patient))

        med = random.choice(MOCK_MEDICATIONS)
        lines.append(f"ORC|RE|ADM{_now()}||||||||||||||||||")
        lines.append(
            f"RXA|0|1|{_now()}||{med['code']}^{med['name']}^NDC|"
            f"{med['dose']}|{med['units']}||||||||LOT{_now()}||"
            f"PHARMA_MFR||||CP"
        )

        return "\r".join(lines) + "\r"


class RGVHandler(BaseHL7Handler):
    """Handle RGV (Pharmacy Give) messages, including PCD-03."""

    def _build_response(self) -> str:
        msg_control_id = self.msh_info.get("message_control_id", "UNKNOWN")

        lines = [_msh_header(self.msh_info, "ACK^O15")]
        lines.append(f"MSA|{_ack_code()}|{msg_control_id}|Pharmacy give recorded")

        patient = random.choice(MOCK_PATIENTS)
        lines.append(_pid_segment(patient))

        med = random.choice(MOCK_MEDICATIONS)
        lines.append(f"ORC|RE|GIV{_now()}||||||||||||||||||")
        lines.append(
            f"RXG|1|1||{med['code']}^{med['name']}^NDC|{med['dose']}||"
            f"{med['units']}|{med['route']}||||||||"
        )

        return "\r".join(lines) + "\r"


class RDSHandler(BaseHL7Handler):
    """Handle RDS (Pharmacy Dispense) messages."""

    def _build_response(self) -> str:
        msg_control_id = self.msh_info.get("message_control_id", "UNKNOWN")

        lines = [_msh_header(self.msh_info, "ACK^O13")]
        lines.append(f"MSA|{_ack_code()}|{msg_control_id}|Pharmacy dispense recorded")

        patient = random.choice(MOCK_PATIENTS)
        lines.append(_pid_segment(patient))

        med = random.choice(MOCK_MEDICATIONS)
        lines.append(f"ORC|RE|DSP{_now()}||||||||||||||||||")
        lines.append(
            f"RXD|1|{med['code']}^{med['name']}^NDC|{_now()}|30|"
            f"{med['units']}||RX{_now()}||||||||||LOT{_now()}|"
        )

        return "\r".join(lines) + "\r"


class VXUHandler(BaseHL7Handler):
    """Handle VXU (Vaccination Update) messages."""

    def _build_response(self) -> str:
        msg_control_id = self.msh_info.get("message_control_id", "UNKNOWN")

        lines = [_msh_header(self.msh_info, "ACK^V04")]
        lines.append(f"MSA|{_ack_code()}|{msg_control_id}|Vaccination update accepted")

        patient = random.choice(MOCK_PATIENTS)
        lines.append(_pid_segment(patient))

        imm = random.choice(MOCK_IMMUNIZATIONS)
        lines.append(
            f"RXA|0|1|{imm['date']}||{imm['code']}^{imm['name']}^CVX|"
            f"1|mL|||||"
            f"||{imm['lot']}||{imm['mfr']}||||CP"
        )

        return "\r".join(lines) + "\r"


class OSQHandler(BaseHL7Handler):
    """Handle OSQ (Order Status Query) messages."""

    def _build_response(self) -> str:
        msg_control_id = self.msh_info.get("message_control_id", "UNKNOWN")

        lines = [_msh_header(self.msh_info, "OSR^Q06")]
        lines.append(f"MSA|{_ack_code()}|{msg_control_id}|Order status query response")
        lines.append("QAK|1|OK|Q06^Order Status Query^HL70471")

        patient = random.choice(MOCK_PATIENTS)
        lines.append(_pid_segment(patient))
        lines.append(_pv1_segment())

        ordering = _provider("ORDERING")
        lines.append(
            f"ORC|SC|ORD{_now()}||GRP001|CM|||^^^{_now()}^^R||{_now()}|"
            f"{ordering['name']}^{ordering['id']}^^^^^NPI||||||||||"
        )
        lines.append(_obr_segment())

        return "\r".join(lines) + "\r"


# ---------------------------------------------------------------------------
# Error handler (NAK responses)
# ---------------------------------------------------------------------------


class HL7ErrorHandler(AbstractErrorHandler):
    """Return proper AE/AR NAK responses for malformed/unsupported messages."""

    def reply(self):
        msh_info = _parse_msh(self.incoming_message) if self.incoming_message else {}
        msg_control_id = msh_info.get("message_control_id", "UNKNOWN")
        version = msh_info.get("version", HL7_VERSION)
        app, facility = _random_app_facility()

        if isinstance(self.exc, UnsupportedMessageType):
            ack_code = "AR"
            ack_text = f"Unsupported message type: {self.exc.msg_type}"
            log.warning("  NAK (AR): %s", ack_text)
        elif isinstance(self.exc, InvalidHL7Message):
            ack_code = "AE"
            ack_text = "Invalid HL7 message format"
            log.warning("  NAK (AE): %s", ack_text)
        else:
            ack_code = "AE"
            ack_text = f"Processing error: {self.exc}"
            log.error("  NAK (AE): %s", ack_text)

        lines = [
            f"MSH|^~\\&|{app}|{facility}|"
            f"{msh_info.get('sending_app', 'UNKNOWN')}|"
            f"{msh_info.get('sending_facility', 'UNKNOWN')}|"
            f"{_now()}||ACK|{_msg_id()}|P|{version}",
            f"MSA|{ack_code}|{msg_control_id}|{ack_text}",
            f"ERR|0|MSH^1^1|207|E|{ack_code}|{ack_text}|||Contact IT at helpdesk@hospital.local",
        ]
        return "\r".join(lines) + "\r"


# ---------------------------------------------------------------------------
# Persistent-connection MLLP request handler
# ---------------------------------------------------------------------------


class PersistentMLLPRequestHandler(StreamRequestHandler):
    """MLLPRequestHandler that supports multiple messages per connection.

    The stock hl7apy MLLPRequestHandler closes after one message.  The OIDA
    scanner sends multiple messages on a single connection, so we loop until
    the client disconnects or times out.
    """

    encoding = "utf-8"

    def setup(self):
        self.sb = b"\x0b"
        self.eb = b"\x1c"
        self.cr = b"\x0d"
        self.validator = re.compile(
            "".join(
                [
                    self.sb.decode("ascii"),
                    r"(([^\r]+\r)*([^\r]+\r?))",
                    self.eb.decode("ascii"),
                    self.cr.decode("ascii"),
                ]
            )
        )
        self.handlers = self.server.handlers
        self.timeout = self.server.timeout
        StreamRequestHandler.setup(self)

    def handle(self):
        client = self.client_address[0]
        log.info("Connection from %s", client)
        self.request.settimeout(self.timeout)

        while True:
            try:
                data = b""
                end_seq = self.eb + self.cr

                # Read until we see MLLP end sequence or disconnect
                while True:
                    chunk = self.request.recv(4096)
                    if not chunk:
                        log.debug("Client %s disconnected", client)
                        return
                    data += chunk
                    if end_seq in data:
                        break

                if not data:
                    return

                message = self._extract_hl7_message(data.decode(self.encoding, errors="ignore"))
                if message is not None:
                    log.info("Received message (%d bytes)", len(message))
                    try:
                        response = self._route_message(message)
                    except Exception as e:
                        log.error("Error routing message: %s", e)
                        return
                    # Wrap response in MLLP framing
                    framed = self.sb + response.encode(self.encoding) + self.eb + self.cr
                    self.request.sendall(framed)
                    log.info("Sent response (%d bytes)", len(response))
                else:
                    log.warning("Received non-HL7 data from %s", client)
                    return

            except socket.timeout:
                log.debug("Connection from %s timed out", client)
                return
            except ConnectionResetError:
                log.debug("Connection from %s reset", client)
                return
            except Exception as e:
                log.error("Error handling message from %s: %s", client, e)
                return

    def _extract_hl7_message(self, msg: str):
        """Extract HL7 message from MLLP frame."""
        matched = self.validator.match(msg)
        if matched is not None:
            return matched.groups()[0]
        # Fallback: strip framing manually
        if msg.startswith("\x0b"):
            msg = msg[1:]
        end_idx = msg.find("\x1c")
        if end_idx >= 0:
            msg = msg[:end_idx]
        if msg.strip():
            return msg
        return None

    def _route_message(self, msg: str) -> str:
        """Route message to appropriate handler."""
        try:
            try:
                msg_type = get_message_type(msg)
            except Exception:
                raise InvalidHL7Message()

            try:
                handler_class, *args = self.handlers[msg_type]
            except KeyError:
                # Try prefix match (e.g., ADT^A01 -> look up "ADT^A01",
                # then fall back to first-component match)
                prefix = msg_type.split("^")[0] if "^" in msg_type else msg_type
                matched = False
                for key in self.handlers:
                    if key == "ERR":
                        continue
                    if key.startswith(prefix + "^") or key == prefix:
                        handler_class, *args = self.handlers[key]
                        matched = True
                        break
                if not matched:
                    raise UnsupportedMessageType(msg_type)

            h = handler_class(msg, *args)
            return h.reply()

        except Exception as e:
            try:
                err_handler_class, *err_args = self.handlers["ERR"]
            except KeyError:
                raise e
            h = err_handler_class(e, msg, *err_args)
            return h.reply()


# ---------------------------------------------------------------------------
# TLS-capable MLLP server
# ---------------------------------------------------------------------------


class TLSMLLPServer(MLLPServer):
    """MLLPServer with optional TLS support."""

    def __init__(self, host, port, handlers, timeout=30, ssl_context=None):
        self.ssl_context = ssl_context
        super().__init__(
            host,
            port,
            handlers,
            timeout=timeout,
            request_handler_class=PersistentMLLPRequestHandler,
        )

    def get_request(self):
        """Wrap accepted sockets with TLS if configured."""
        client_socket, client_address = self.socket.accept()
        if self.ssl_context:
            try:
                client_socket = self.ssl_context.wrap_socket(client_socket, server_side=True)
            except ssl.SSLError as e:
                log.warning("TLS handshake failed from %s: %s", client_address, e)
                client_socket.close()
                raise
        return client_socket, client_address


def _generate_self_signed_cert(cert_dir: str = "/tmp/hl7-certs"):
    """Generate a self-signed certificate for MLLPS testing."""
    os.makedirs(cert_dir, exist_ok=True)
    cert_path = os.path.join(cert_dir, "server.pem")
    key_path = os.path.join(cert_dir, "server.key")

    if os.path.exists(cert_path) and os.path.exists(key_path):
        log.info("Using existing self-signed certs: %s", cert_dir)
        return cert_path, key_path

    log.info("Generating self-signed certificate...")
    try:
        subprocess.run(
            [
                "openssl",
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-keyout",
                key_path,
                "-out",
                cert_path,
                "-days",
                "365",
                "-nodes",
                "-subj",
                "/CN=hl7-mock-server/O=OIDA/C=US",
            ],
            check=True,
            capture_output=True,
        )
        log.info("Self-signed cert generated: %s", cert_path)
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        log.warning("openssl not available, generating cert with Python ssl: %s", e)
        # Fallback: use Python to generate a basic self-signed cert
        import tempfile

        _generate_cert_python(cert_path, key_path)

    return cert_path, key_path


def _generate_cert_python(cert_path: str, key_path: str):
    """Generate self-signed cert using Python (no openssl binary needed)."""
    try:
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        import datetime as dt

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = issuer = x509.Name(
            [
                x509.NameAttribute(NameOID.COMMON_NAME, "hl7-mock-server"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "OIDA"),
            ]
        )
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(dt.datetime.utcnow())
            .not_valid_after(dt.datetime.utcnow() + dt.timedelta(days=365))
            .sign(key, hashes.SHA256())
        )
        with open(key_path, "wb") as f:
            f.write(
                key.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.TraditionalOpenSSL,
                    serialization.NoEncryption(),
                )
            )
        with open(cert_path, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        log.info("Self-signed cert generated via Python cryptography: %s", cert_path)
    except ImportError:
        log.error("Neither openssl nor cryptography package available for cert generation")
        raise


def _build_ssl_context() -> ssl.SSLContext:
    """Build SSL context from environment variables."""
    cert_path = os.environ.get("TLS_CERT")
    key_path = os.environ.get("TLS_KEY")
    ca_path = os.environ.get("TLS_CA")

    if not cert_path or not key_path:
        cert_path, key_path = _generate_self_signed_cert()

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)

    if ca_path:
        ctx.load_verify_locations(cafile=ca_path)
        ctx.verify_mode = ssl.CERT_OPTIONAL
    else:
        ctx.verify_mode = ssl.CERT_NONE

    log.info("TLS context configured: cert=%s, ca=%s", cert_path, ca_path or "none")
    return ctx


# ---------------------------------------------------------------------------
# Handler routing table
# ---------------------------------------------------------------------------


def _build_handler_map() -> dict:
    """Build the handler dictionary for MLLPServer.

    Keys are message types as returned by hl7apy's get_message_type()
    (e.g., "ADT^A01").  We register broad patterns so that any ADT
    trigger routes to the same handler.
    """
    handlers = {}

    # ADT triggers
    for trigger in [
        "A01",
        "A02",
        "A03",
        "A04",
        "A05",
        "A08",
        "A11",
        "A12",
        "A13",
        "A28",
        "A31",
        "A40",
    ]:
        handlers[f"ADT^{trigger}"] = (ADTHandler,)

    # QRY triggers
    for trigger in ["Q01", "A19", "R02"]:
        handlers[f"QRY^{trigger}"] = (QRYHandler,)

    # ORM
    handlers["ORM^O01"] = (ORMHandler,)

    # ORU (including PCD-01 device observations and PCD-10 alarms)
    for trigger in ["R01", "R40", "R42"]:
        handlers[f"ORU^{trigger}"] = (ORUHandler,)
    # Three-component form
    handlers["ORU^R01^ORU_R01"] = (ORUHandler,)
    handlers["ORU^R42^ORU_R01"] = (ORUHandler,)

    # SIU
    for trigger in ["S12", "S13", "S14", "S15", "S16", "S17", "S26"]:
        handlers[f"SIU^{trigger}"] = (SIUHandler,)

    # MDM
    for trigger in ["T01", "T02", "T03", "T04", "T05", "T06", "T11"]:
        handlers[f"MDM^{trigger}"] = (MDMHandler,)

    # MFN
    for trigger in ["M01", "M02", "M04"]:
        handlers[f"MFN^{trigger}"] = (MFNHandler,)

    # MFQ
    handlers["MFQ^M01"] = (MFQHandler,)

    # QBP
    for trigger in ["Q13", "Q40", "Z34", "Z44", "Q11"]:
        handlers[f"QBP^{trigger}"] = (QBPHandler,)
    handlers["QBP^Q40^QBP_Q13"] = (QBPHandler,)
    handlers["QBP^Q13^QBP_Q13"] = (QBPHandler,)
    handlers["QBP^Z34^QBP_Q11"] = (QBPHandler,)
    handlers["QBP^Z44^QBP_Q11"] = (QBPHandler,)

    # BAR
    for trigger in ["P01", "P02", "P05", "P06"]:
        handlers[f"BAR^{trigger}"] = (BARHandler,)

    # DFT
    handlers["DFT^P03"] = (DFTHandler,)

    # Pharmacy messages
    handlers["RDE^O11"] = (RDEHandler,)
    handlers["RAS^O17"] = (RASHandler,)
    handlers["RGV^O15"] = (RGVHandler,)
    handlers["RGV^O15^RGV_O15"] = (RGVHandler,)
    handlers["RDS^O13"] = (RDSHandler,)

    # VXU (Vaccination Update)
    handlers["VXU^V04"] = (VXUHandler,)

    # OSQ (Order Status Query)
    handlers["OSQ^Q06"] = (OSQHandler,)

    # ACK (generic)
    handlers["ACK"] = (BaseHL7Handler,)

    # Error handler (NAK for unsupported/invalid messages)
    handlers["ERR"] = (HL7ErrorHandler,)

    return handlers


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main():
    host = "0.0.0.0"
    port = int(os.environ.get("HL7_PORT", "2575"))
    enable_tls = os.environ.get("ENABLE_TLS", "").strip() in ("1", "true", "yes")
    tls_port = int(os.environ.get("HL7_TLS_PORT", "2576"))

    log.info("Starting Mock HL7 MLLP Server")
    log.info("  Server Application: %s", SERVER_APP)
    log.info("  Server Facility: %s", SERVER_FACILITY)
    log.info("  Response Mode: %s", RESPONSE_MODE)

    log.info("Mock database contents:")
    log.info("  Applications: %d (for --enum-apps)", len(MOCK_APPS))
    log.info("  Providers: %d (for --enum-providers)", len(MOCK_PROVIDERS))
    log.info("  Locations: %d (for --enum-locations)", len(MOCK_LOCATIONS))
    log.info("  Patients: %d", len(MOCK_PATIENTS))
    log.info("  Medications: %d", len(MOCK_MEDICATIONS))
    log.info("  Immunizations: %d", len(MOCK_IMMUNIZATIONS))
    log.info("  Staff: %d (MFN^M02)", len(MOCK_STAFF))
    log.info("  Charges: %d (MFN^M04)", len(MOCK_CHARGES))
    log.info("  Schedules: %d (SIU)", len(MOCK_SCHEDULES))
    log.info("  Documents: %d (MDM)", len(MOCK_DOCUMENTS))

    handlers = _build_handler_map()
    handler_count = len([k for k in handlers if k != "ERR"])
    log.info("  Registered handlers: %d message types", handler_count)

    # Start plain MLLP server
    plain_server = TLSMLLPServer(host, port, handlers, timeout=30)
    log.info("MLLP listening on %s:%d", host, port)

    # Optionally start TLS server on separate port
    tls_server = None
    if enable_tls:
        try:
            ssl_ctx = _build_ssl_context()
            tls_server = TLSMLLPServer(host, tls_port, handlers, timeout=30, ssl_context=ssl_ctx)
            log.info("MLLPS (TLS) listening on %s:%d", host, tls_port)
        except Exception as e:
            log.error("Failed to start TLS server: %s", e)

    try:
        if tls_server:
            tls_thread = threading.Thread(target=tls_server.serve_forever, daemon=True)
            tls_thread.start()
        plain_server.serve_forever()
    except KeyboardInterrupt:
        log.info("Server shutting down")
        plain_server.shutdown()
        if tls_server:
            tls_server.shutdown()


if __name__ == "__main__":
    main()
