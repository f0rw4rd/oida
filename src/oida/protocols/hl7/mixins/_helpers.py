"""
Shared helpers for HL7 mixin message construction.

Extracts common patterns (MSH population, QRD/RCP segment building)
to eliminate duplication across mixin modules.
"""

import time
from datetime import datetime

from hl7apy.core import Message, Segment


def populate_msh(
    msg: Message,
    args,
    *,
    version: str,
    msg_type: str,
    control_prefix: str,
    receiving_app: str = "TARGET",
    receiving_facility: str = "FACILITY",
    sending_app: str | None = None,
    sending_facility: str | None = None,
) -> None:
    """Populate MSH segment fields on a message.

    Args:
        msg: HL7 Message with msh segment.
        args: CLI args namespace (for sending_app/sending_facility overrides).
        version: HL7 version string.
        msg_type: Message type string for MSH-9 (e.g. "QRY^Q01").
        control_prefix: Prefix for MSH-10 control ID (e.g. "QRY").
        receiving_app: MSH-5 value.
        receiving_facility: MSH-6 value.
        sending_app: Override for MSH-3 (defaults to args.sending_app or "OIDA").
        sending_facility: Override for MSH-4 (defaults to args.sending_facility or "SECURITY").
    """
    msh = msg.msh
    msh.msh_3 = sending_app or getattr(args, "sending_app", "OIDA")
    msh.msh_4 = sending_facility or getattr(args, "sending_facility", "SECURITY")
    msh.msh_5 = receiving_app
    msh.msh_6 = receiving_facility
    msh.msh_7 = datetime.now().strftime("%Y%m%d%H%M%S")
    msh.msh_9 = msg_type
    msh.msh_10 = f"{control_prefix}{int(time.time())}"
    msh.msh_11 = "P"
    msh.msh_12 = version


def build_qrd(
    version: str,
    *,
    query_id_prefix: str,
    who_subject: str = "*",
    what_subject: str | None = None,
    what_dept: str | None = None,
    result_format: str | None = None,
) -> Segment:
    """Build a QRD (Query Definition) segment.

    Args:
        version: HL7 version string.
        query_id_prefix: Prefix for QRD-4 query ID.
        who_subject: QRD-8 who subject filter (default "*").
        what_subject: QRD-9 what subject filter (optional).
        what_dept: QRD-10 what department (optional).
        result_format: QRD-7 quantity limited request (optional, e.g. "RD").

    Returns:
        Populated QRD Segment.
    """
    qrd = Segment("QRD", version=version)
    qrd.qrd_1 = datetime.now().strftime("%Y%m%d%H%M%S")
    qrd.qrd_2 = "R"  # Response type: Real-time
    qrd.qrd_3 = "I"  # Response priority: Immediate
    qrd.qrd_4 = f"{query_id_prefix}{int(time.time())}"
    if result_format:
        qrd.qrd_7 = result_format
    qrd.qrd_8 = who_subject
    if what_subject:
        qrd.qrd_9 = what_subject
    if what_dept:
        qrd.qrd_10 = what_dept
    return qrd


def build_rcp(version: str) -> Segment:
    """Build an RCP (Response Control Parameters) segment.

    Args:
        version: HL7 version string.

    Returns:
        Populated RCP Segment (RCP-1 "I" Immediate, RCP-2 "999^RD").
    """
    rcp = Segment("RCP", version=version)
    rcp.rcp_1 = "I"  # Query priority: Immediate
    rcp.rcp_2 = "999^RD"  # Quantity limited request
    return rcp
