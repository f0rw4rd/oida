"""
HL7 Protocol Utilities

Shared utility functions for HL7 message creation and parsing.
Used by both the protocol scanner and the fuzzer.
"""

import time
from datetime import datetime
from typing import Any, Dict, Optional, Tuple

# hl7apy is gated by HL7APY_AVAILABLE in __init__.py — if the user runs
# `oida hl7 …` without the optional `hl7` extra installed, that check
# fails fast with a friendly install hint. The try/except here protects
# against transitive import paths that pull this file in before the gate
# has run (e.g. fuzzer modules importing create_test_message directly).
try:
    from hl7apy.core import Message
except ImportError:  # pragma: no cover — release-checked dep
    Message = None  # type: ignore[assignment]

from .segments import HL7SegmentBuilder
from ...utils.protocol_helpers import ConnectionHelper

import logging

logger = logging.getLogger(__name__)


# MLLP framing characters (canonical definition, re-exported by __init__.py)
MLLP_START = b"\x0b"  # VT (vertical tab)
MLLP_END = b"\x1c\x0d"  # FS + CR


def create_test_message(
    msg_type: str,
    trigger_event: str,
    version: str = "2.5",
    sending_app: str = "OIDA",
    sending_facility: str = "SECURITY",
    receiving_app: str = "TARGET",
    receiving_facility: str = "FACILITY",
    processing_id: str = "P",
    segment_builder: Optional[HL7SegmentBuilder] = None,
) -> Optional[str]:
    """Create an HL7 test message for probing server capabilities.

    Args:
        msg_type: Message type (e.g., 'ADT', 'ORU', 'ORM')
        trigger_event: Trigger event (e.g., 'A01', 'R01', 'O01')
        version: HL7 version (default: '2.5')
        sending_app: Sending application name (MSH-3)
        sending_facility: Sending facility name (MSH-4)
        receiving_app: Receiving application name (MSH-5)
        receiving_facility: Receiving facility name (MSH-6)
        processing_id: Processing ID (P, D, or T)
        segment_builder: Optional HL7SegmentBuilder for segment creation

    Returns:
        HL7 message string (without MLLP framing) or None
    """
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    msg_id = f"MSG{int(time.time())}"

    # Try hl7apy first for supported message types
    try:
        msg = Message(f"{msg_type}_{trigger_event}", version=version)
        msh = msg.msh
        msh.msh_3 = sending_app
        msh.msh_4 = sending_facility
        msh.msh_5 = receiving_app
        msh.msh_6 = receiving_facility
        msh.msh_7 = timestamp
        msh.msh_9 = f"{msg_type}^{trigger_event}"
        msh.msh_10 = msg_id
        msh.msh_11 = processing_id
        msh.msh_12 = version

        # Add segments based on message type
        if segment_builder is None:
            segment_builder = HL7SegmentBuilder(version=version)

        if msg_type == "ADT":
            msg.evn.evn_1 = trigger_event
            msg.evn.evn_2 = timestamp
            pid = segment_builder.build_pid(
                patient_id="PROBE",
                patient_name="PROBE^PATIENT",
                dob="19800101",
                sex="M",
            )
            if pid:
                msg.add(pid)
            pv1 = segment_builder.build_pv1(
                patient_class="I",
                location="PROBE^101^A",
            )
            if pv1:
                msg.add(pv1)

        elif msg_type == "ORU":
            pid = segment_builder.build_pid(
                patient_id="PROBE",
                patient_name="PROBE^PATIENT",
            )
            if pid:
                msg.add(pid)
            obr = segment_builder.build_obr(
                order_id="ORD001",
                filler_order="FIL001",
                service_id="85025^CBC^L",
            )
            if obr:
                msg.add(obr)
            obx = segment_builder.build_obx(
                value_type="NM",
                observation_id="1234-5^WBC^LN",
                observation_value="7.5",
                units="K/uL",
            )
            if obx:
                msg.add(obx)

        elif msg_type == "ORM":
            pid = segment_builder.build_pid(
                patient_id="PROBE",
                patient_name="PROBE^PATIENT",
            )
            if pid:
                msg.add(pid)
            orc = segment_builder.build_orc(
                order_control="NW",
                placer_order="ORD001",
            )
            if orc:
                msg.add(orc)
            obr = segment_builder.build_obr(
                order_id="ORD001",
                service_id="85025^CBC^L",
            )
            if obr:
                msg.add(obr)

        elif msg_type == "QRY":
            msg.qrd.qrd_1 = timestamp
            msg.qrd.qrd_2 = "R"
            msg.qrd.qrd_3 = "I"
            msg.qrd.qrd_4 = "QRY001"
            msg.qrd.qrd_7 = "RD"
            msg.qrd.qrd_8 = "PROBE^^^MRN"
            msg.qrd.qrd_9 = "DEM"

        elif msg_type == "ACK":
            msg.msa.msa_1 = "AA"
            msg.msa.msa_2 = msg_id

        return msg.to_er7()

    except Exception as e:
        logger.debug(f"Operation failed: {e}")

    # Fallback: create raw HL7 message for unsupported types
    msh = (
        f"MSH|^~\\&|{sending_app}|{sending_facility}|"
        f"{receiving_app}|{receiving_facility}|{timestamp}||"
        f"{msg_type}^{trigger_event}|{msg_id}|{processing_id}|{version}"
    )

    segments = [msh]
    if msg_type == "ADT":
        segments.append(f"EVN|{trigger_event}|{timestamp}")
        segments.append("PID|1||PROBE^^^MRN||PROBE^PATIENT||19800101|M")
        segments.append("PV1|1|I|PROBE^101^A")
    elif msg_type == "QBP":
        segments.append(f"QPD|{trigger_event}|Q001|PROBE^^^MRN")
        segments.append("RCP|I|10^RD")
    else:
        segments.append("PID|1||PROBE^^^MRN||PROBE^PATIENT||19800101|M")

    return "\r".join(segments)


def wrap_mllp(message: str) -> bytes:
    """Wrap HL7 message string with MLLP framing.

    Args:
        message: HL7 message string

    Returns:
        MLLP-framed message bytes
    """
    return MLLP_START + message.encode("utf-8") + MLLP_END


def strip_mllp(response: bytes) -> bytes:
    """Strip MLLP framing from response.

    Args:
        response: Raw MLLP response

    Returns:
        HL7 message without MLLP framing
    """
    if response.startswith(MLLP_START):
        response = response[1:]
    if MLLP_END in response:
        response = response.split(MLLP_END)[0]
    return response


def extract_ack_code(response: bytes) -> Optional[str]:
    """Extract acknowledgment code from HL7 ACK response.

    Args:
        response: Raw MLLP response

    Returns:
        ACK code (AA, AE, AR, CA, CE, CR) or None
    """
    try:
        response = strip_mllp(response)
        text = response.decode("utf-8", errors="ignore")
        segments = text.split("\r")

        for segment in segments:
            fields = segment.split("|")
            if fields and fields[0] == "MSA" and len(fields) > 1:
                return fields[1]

    except Exception as e:
        logger.debug(f"Failed to get response: {e}")

    return None


def parse_ack_response(response: bytes) -> Dict[str, Any]:
    """Parse HL7 ACK response to extract server info.

    Args:
        response: Raw MLLP response

    Returns:
        Dictionary with server_app, server_facility, version
    """
    result = {
        "server_app": None,
        "server_facility": None,
        "version": None,
    }

    try:
        response = strip_mllp(response)
        text = response.decode("utf-8", errors="ignore")
        segments = text.split("\r")

        for segment in segments:
            fields = segment.split("|")
            if not fields:
                continue

            seg_id = fields[0]

            if seg_id == "MSH" and len(fields) > 11:
                # MSH-3: Sending Application (server responding)
                if len(fields) > 2 and fields[2]:
                    result["server_app"] = fields[2]
                # MSH-4: Sending Facility
                if len(fields) > 3 and fields[3]:
                    result["server_facility"] = fields[3]
                # MSH-12: Version ID
                if len(fields) > 11 and fields[11]:
                    result["version"] = fields[11].split("^")[0]

    except Exception as e:
        logger.debug(f"Operation failed: {e}")

    return result


def send_probe(
    host: str,
    port: int,
    msg_type: str,
    trigger_event: str,
    timeout: float = 3.0,
    **kwargs,
) -> Tuple[Optional[bytes], Optional[str]]:
    """Send a probe message and receive response.

    Args:
        host: Target hostname or IP
        port: Target port
        msg_type: Message type (e.g., 'ADT')
        trigger_event: Trigger event (e.g., 'A01')
        timeout: Socket timeout in seconds
        **kwargs: Additional arguments for create_test_message

    Returns:
        Tuple of (response bytes, ack_code) or (None, None)
    """
    message = create_test_message(msg_type, trigger_event, **kwargs)
    if not message:
        return None, None

    sock = ConnectionHelper.create_tcp_socket(host, port, timeout=timeout)

    try:
        sock.send(wrap_mllp(message))

        # Receive response with a hard cap so a peer that never sends MLLP_END
        # can't drive us to OOM.
        MAX_HL7_RESPONSE = 16 * 1024 * 1024  # 16 MiB
        response = b""
        while True:
            try:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
                if MLLP_END in response:
                    break
                if len(response) > MAX_HL7_RESPONSE:
                    break
            except TimeoutError:
                break

        if response:
            ack_code = extract_ack_code(response)
            return response, ack_code

        return None, None

    finally:
        sock.close()


def probe_server_capabilities(
    host: str,
    port: int = 2575,
    timeout: float = 3.0,
    **kwargs,
) -> Dict[str, Any]:
    """Probe HL7 server to detect supported message types.

    Args:
        host: Target hostname or IP
        port: Target port (default: 2575)
        timeout: Socket timeout in seconds
        **kwargs: Additional arguments for create_test_message

    Returns:
        Dictionary with detected capabilities
    """
    capabilities = {
        "message_types": set(),
        "rejected_types": set(),
        "server_app": None,
        "server_facility": None,
        "detected_version": None,
        "mllp_supported": False,
    }

    # Message types to probe — READ-ONLY ONLY.
    # The original list included ADT^A01 (admit patient), ORU^R01 (observation
    # result), ORM^O01 (order) — all server-side WRITES. A defensive scanner
    # must never create records on the target by default; if the operator
    # wants to probe write-message-type acceptance they go through
    # `--probe-ops --confirm` in the main CLI, not via this importable
    # helper that takes no args/namespace and offers no opt-out.
    probe_messages = [
        ("ACK", ""),
        ("QRY", "A19"),  # Display-style query (read-only)
        ("QBP", "Q11"),  # Display-Based Response (read-only fingerprint)
        ("QBP", "Q40"),  # WhoAmI query (read-only identity)
    ]

    for msg_type, trigger in probe_messages:
        response, ack_code = send_probe(host, port, msg_type, trigger, timeout=timeout, **kwargs)

        if response:
            capabilities["mllp_supported"] = True

            # Parse server info from first response
            if capabilities["server_app"] is None:
                info = parse_ack_response(response)
                capabilities["server_app"] = info.get("server_app")
                capabilities["server_facility"] = info.get("server_facility")
                capabilities["detected_version"] = info.get("version")

            # Categorize by ACK code
            if ack_code in ("AA", "CA"):
                capabilities["message_types"].add(msg_type)
            elif ack_code in ("AE", "CE"):
                # Error but understood - still supported
                capabilities["message_types"].add(msg_type)
            elif ack_code in ("AR", "CR"):
                capabilities["rejected_types"].add(msg_type)
            else:
                # Unknown response, assume supported
                capabilities["message_types"].add(msg_type)
        else:
            # No response, assume supported (may be one-way)
            capabilities["message_types"].add(msg_type)

    return capabilities
