"""
HL7 v2 Passive Listener for healthcare messaging traffic analysis (ICS).

Passively captures HL7 v2.x (Health Level Seven) protocol traffic to extract:
- Message types (ADT, ORM, ORU, SIU, MDM, DFT, etc.)
- Trigger events (A01=Admit, A02=Transfer, A03=Discharge, etc.)
- Sending and receiving applications/facilities
- Message control IDs for message flow tracking
- Raw segment types (MSH, PID, PV1, OBR, OBX, etc.)

HL7 v2 is the dominant healthcare messaging standard used for:
- Patient admission/discharge/transfer (ADT)
- Lab orders and results (ORM/ORU)
- Scheduling (SIU)
- Clinical documentation (MDM)
- Billing/financial (DFT/BAR)

HL7 v2 runs over TCP (MLLP - Minimal Lower Layer Protocol) on port 2575.
MLLP wraps HL7 messages with SOB (0x0B) and EOB (0x1C 0x0D) delimiters.

Security concerns:
- HL7 v2 has no built-in encryption (PHI in cleartext by default)
- No authentication mechanism in the protocol
- Message routing changes can redirect patient data
- Patient identifiers (MRN, SSN) transmitted in PID segments
- Lab results in OBX segments may contain sensitive diagnostics

tshark fields used:
- hl7.raw: Complete raw HL7 message (FT_STRING)
- hl7.raw.segment: Individual raw segment (FT_STRING)
- hl7.segment: Segment identifier (FT_STRING)
- hl7.message.type: Message type from MSH-9 (FT_STRING)
- hl7.event.type: Trigger event from MSH-9 (FT_STRING)
- hl7.field: Generic field content (FT_STRING)
- hl7.llp.sob: LLP Start Of Block marker (FT_UINT8, 0x0B)
- hl7.llp.eob: LLP End Of Block marker (FT_UINT16, 0x1C0D)

References:
- HL7 v2.x Standard (www.hl7.org)
- MLLP: HL7 v2 Transport Specification
- Wireshark dissector: packet-hl7.c
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Tuple

from .pyshark_base import ProtocolInteraction, PySharkListenerBase
from ..protocols.discovery.core import is_valid_discovered_ip, lookup_mac_vendor

# HL7 message types (MSH-9.1)
HL7_MESSAGE_TYPES = {
    "ACK": "General Acknowledgment",
    "ADT": "Admit/Discharge/Transfer",
    "BAR": "Add/Change Billing Account",
    "DFT": "Detailed Financial Transaction",
    "MDM": "Medical Document Management",
    "MFN": "Master Files Notification",
    "OML": "Laboratory Order",
    "ORM": "Order Message (General)",
    "ORU": "Observation Result (Unsolicited)",
    "OUL": "Unsolicited Lab Observation",
    "QBP": "Query By Parameter",
    "QRY": "Query",
    "RAS": "Pharmacy/Treatment Administration",
    "RDE": "Pharmacy/Treatment Encoded Order",
    "RDS": "Pharmacy/Treatment Dispense",
    "RGV": "Pharmacy/Treatment Give",
    "RSP": "Response to Query",
    "SIU": "Schedule Information Unsolicited",
    "SRM": "Schedule Request",
    "VXU": "Vaccination Record Update",
    "PPR": "Patient Problem",
    "PTR": "Patient Pathway (Problem-Oriented)",
    "RPA": "Return Patient Authorization",
    "RPR": "Return Patient Display",
    "TCU": "Automated Equipment Test Code Settings Update",
    "MFK": "Master Files Application Acknowledgment",
}

# HL7 ADT trigger events (A01-A62, common subset)
HL7_ADT_EVENTS = {
    "A01": "Admit/Visit Notification",
    "A02": "Transfer a Patient",
    "A03": "Discharge/End Visit",
    "A04": "Register a Patient",
    "A05": "Pre-Admit a Patient",
    "A06": "Change Outpatient to Inpatient",
    "A07": "Change Inpatient to Outpatient",
    "A08": "Update Patient Information",
    "A09": "Patient Departing (Tracking)",
    "A10": "Patient Arriving (Tracking)",
    "A11": "Cancel Admit",
    "A12": "Cancel Transfer",
    "A13": "Cancel Discharge",
    "A14": "Pending Admit",
    "A15": "Pending Transfer",
    "A16": "Pending Discharge",
    "A17": "Swap Patients",
    "A18": "Merge Patient Information",
    "A23": "Delete a Patient Record",
    "A28": "Add Person Information",
    "A31": "Update Person Information",
    "A34": "Merge Patient (ID Only)",
    "A38": "Cancel Pre-Admit",
    "A40": "Merge Patient (Account)",
    "A44": "Move Account (Patient Account)",
    "A45": "Move Visit Information (Visit)",
    "A47": "Change Patient Identifier List",
    "A54": "Change Attending Doctor",
    "A60": "Update Allergy Information",
    "A62": "Cancel Change Attending Doctor",
}

# HL7 ORM/ORU trigger events
HL7_ORDER_EVENTS = {
    "O01": "Order Message",
    "O02": "Order Response",
    "R01": "Unsolicited Result",
    "R30": "Unsolicited Point-of-Care Result",
    "R31": "Unsolicited Lab Observation",
    "R32": "Unsolicited Pre-Ordered Point-of-Care Result",
}

# Segments containing PHI
PHI_SEGMENTS = {"PID", "NK1", "GT1", "IN1", "AL1", "DG1", "OBX", "NTE"}


@dataclass
class HL7Interface:
    """Track an HL7 interface (sending/receiving application pair)."""

    sending_app: str
    receiving_app: str
    client_ip: str
    server_ip: str
    message_types: Set[str] = field(default_factory=set)
    trigger_events: Set[str] = field(default_factory=set)
    segments_seen: Set[str] = field(default_factory=set)
    message_count: int = 0
    phi_segments_seen: bool = False
    first_seen: str = ""
    last_seen: str = ""


class HL7PassiveListener(PySharkListenerBase):
    """Passive HL7 v2 traffic listener for healthcare messaging analysis.

    Captures HL7 v2.x traffic (over MLLP/TCP) to extract:
    - Message types and trigger events
    - Sending/receiving applications
    - Segment types (PID, OBR, OBX, etc.)
    - PHI exposure indicators
    - Message flow patterns
    """

    PROTOCOL_NAME = "hl7"
    DISPLAY_FILTER = "hl7"
    REQUIRED_LAYERS = ("hl7",)
    SERVER_PORTS = (2575,)
    PROTOCOL_COLUMNS = ("msg_type", "event", "sending_app", "receiving_app", "detail")

    def __init__(
        self,
        interface: str,
        timeout: int = 60,
        nxc_logger: Optional[Any] = None,
    ):
        super().__init__(interface, timeout, nxc_logger)
        self.interfaces: Dict[Tuple[str, str], HL7Interface] = {}

    def process_packet(self, packet) -> None:
        """Process HL7 v2 packet."""
        if not hasattr(packet, "hl7"):
            return

        hl7 = packet.hl7
        src_ip, dst_ip = self.get_ip_info(packet)
        if not src_ip or not dst_ip:
            return

        flow_id = self.get_flow_id(packet)
        src_port, dst_port = self.get_port_info(packet)
        stream_id = self.get_stream_id(packet)
        src_mac, dst_mac = self.get_mac_info(packet)
        now = datetime.now().isoformat()

        # Get message type and event type from tshark fields
        msg_type = str(self.get_field(hl7, "message_type", "") or "").strip()
        if not msg_type:
            msg_type = str(self.get_field(hl7, "message.type", "") or "").strip()
        event_type = str(self.get_field(hl7, "event_type", "") or "").strip()
        if not event_type:
            event_type = str(self.get_field(hl7, "event.type", "") or "").strip()

        # Get segment identifiers
        segment = str(self.get_field(hl7, "segment", "") or "").strip()
        raw_segment = str(self.get_field(hl7, "raw_segment", "") or "").strip()
        if not raw_segment:
            raw_segment = str(self.get_field(hl7, "raw.segment", "") or "").strip()

        # Get raw message for parsing when tshark fields are minimal
        raw_msg = str(self.get_field(hl7, "raw", "") or "").strip()

        # Parse MSH from raw message if needed
        sending_app = ""
        receiving_app = ""
        sending_facility = ""
        receiving_facility = ""
        msg_control_id = ""

        if raw_msg and raw_msg.startswith("MSH"):
            parsed = self._parse_msh(raw_msg)
            sending_app = parsed.get("sending_app", "")
            receiving_app = parsed.get("receiving_app", "")
            sending_facility = parsed.get("sending_facility", "")
            receiving_facility = parsed.get("receiving_facility", "")
            msg_control_id = parsed.get("msg_control_id", "")
            if not msg_type:
                msg_type = parsed.get("msg_type", "")
            if not event_type:
                event_type = parsed.get("event_type", "")

        # Also try parsing from raw_segment if it starts with MSH
        if not sending_app and raw_segment and raw_segment.startswith("MSH"):
            parsed = self._parse_msh(raw_segment)
            sending_app = parsed.get("sending_app", "")
            receiving_app = parsed.get("receiving_app", "")
            sending_facility = parsed.get("sending_facility", "")
            receiving_facility = parsed.get("receiving_facility", "")
            msg_control_id = parsed.get("msg_control_id", "")
            if not msg_type:
                msg_type = parsed.get("msg_type", "")
            if not event_type:
                event_type = parsed.get("event_type", "")

        # Determine segments present in message (from raw)
        segments_in_msg: Set[str] = set()
        if segment:
            segments_in_msg.add(segment)
        if raw_msg:
            for line in raw_msg.replace("\\r", "\r").replace("\\n", "\n").split("\r"):
                line = line.strip()
                if len(line) >= 3 and line[:3].isalpha():
                    segments_in_msg.add(line[:3])

        # Check for PHI segments
        has_phi = bool(segments_in_msg & PHI_SEGMENTS)

        # Get names
        msg_type_name = HL7_MESSAGE_TYPES.get(msg_type, msg_type)
        event_name = ""
        if msg_type == "ADT" and event_type:
            event_name = HL7_ADT_EVENTS.get(event_type, event_type)
        elif msg_type in ("ORM", "ORU") and event_type:
            event_name = HL7_ORDER_EVENTS.get(event_type, event_type)
        elif event_type:
            event_name = event_type

        # Determine direction via the shared cascade.  An ACK message type is a
        # clean port-independent response signal (native=False); everything else
        # has no request/response indicator, so native=None falls through to the
        # known-server-port tier (canonical 2575 plus any user --decode-as /
        # OVERRIDE_PREFS override) and then the lower-port / first-seen
        # heuristic.  Unlike the old `dst_port == 2575` checks this never drops
        # traffic on a non-standard port.
        native = False if msg_type == "ACK" else None
        d = self.resolve_direction(
            packet,
            native=native,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            flow_id=flow_id,
        )
        direction = d.direction

        details: Dict[str, Any] = {}
        if msg_type:
            details["message_type"] = msg_type
            details["message_type_name"] = msg_type_name
        if event_type:
            details["trigger_event"] = event_type
            if event_name:
                details["trigger_event_name"] = event_name
        if sending_app:
            details["sending_app"] = sending_app
        if receiving_app:
            details["receiving_app"] = receiving_app
        if sending_facility:
            details["sending_facility"] = sending_facility
        if receiving_facility:
            details["receiving_facility"] = receiving_facility
        if msg_control_id:
            details["msg_control_id"] = msg_control_id
        if segments_in_msg:
            details["segments"] = sorted(segments_in_msg)
        if has_phi:
            details["phi_segments_present"] = True

        # Build operation and summary
        operation = f"{msg_type}^{event_type}" if msg_type and event_type else msg_type or "HL7"
        summary_parts = []
        if msg_type_name:
            summary_parts.append(msg_type_name)
        if event_name and event_name != event_type:
            summary_parts.append(f"({event_name})")
        elif event_type:
            summary_parts.append(f"^{event_type}")
        if sending_app and receiving_app:
            summary_parts.append(f"{sending_app}->{receiving_app}")
        if has_phi:
            summary_parts.append("[PHI]")
        summary = " ".join(summary_parts) or "HL7 message"

        self._record_interaction(
            now,
            src_ip,
            dst_ip,
            direction,
            operation,
            details,
            summary,
            flow_id=flow_id,
            src_port=src_port,
            dst_port=dst_port,
            stream_id=stream_id,
        )

        # Track interface. Key on the *resolved* client/server roles, not raw
        # src_ip/dst_ip -- an ACK response (server->client) would otherwise
        # create a role-reversed duplicate interface entry keyed on its
        # reversed (src, dst) pair.
        self._track_interface(
            d.client_ip,
            d.server_ip,
            sending_app,
            receiving_app,
            msg_type,
            event_type,
            segments_in_msg,
            has_phi,
            now,
        )

        # Update devices
        self._update_devices(src_ip, dst_ip, src_mac, dst_mac, sending_app, receiving_app)

    @staticmethod
    def _parse_msh(raw: str) -> Dict[str, str]:
        """Parse MSH segment fields from raw message.

        MSH format: MSH|^~\\&|SendApp|SendFac|RecvApp|RecvFac|DateTime||MsgType^Event|ControlID|...
        Field separator is the 4th character (usually |).
        """
        result: Dict[str, str] = {}
        if len(raw) < 4:
            return result

        sep = raw[3]  # Field separator (usually |)
        fields = raw.split(sep)

        # MSH-3: Sending Application
        if len(fields) > 2:
            result["sending_app"] = fields[2].strip()
        # MSH-4: Sending Facility
        if len(fields) > 3:
            result["sending_facility"] = fields[3].strip()
        # MSH-5: Receiving Application
        if len(fields) > 4:
            result["receiving_app"] = fields[4].strip()
        # MSH-6: Receiving Facility
        if len(fields) > 5:
            result["receiving_facility"] = fields[5].strip()
        # MSH-9: Message Type^Trigger Event
        if len(fields) > 8:
            msg_field = fields[8].strip()
            parts = msg_field.split("^")
            if parts:
                result["msg_type"] = parts[0]
            if len(parts) > 1:
                result["event_type"] = parts[1]
        # MSH-10: Message Control ID
        if len(fields) > 9:
            result["msg_control_id"] = fields[9].strip()

        return result

    def _track_interface(
        self,
        client_ip: str,
        server_ip: str,
        sending_app: str,
        receiving_app: str,
        msg_type: str,
        event_type: str,
        segments: Set[str],
        has_phi: bool,
        now: str,
    ) -> None:
        """Track an HL7 interface. Callers must pass resolved client/server IPs."""
        key = (client_ip, server_ip)
        if key not in self.interfaces:
            self.interfaces[key] = HL7Interface(
                sending_app=sending_app or "",
                receiving_app=receiving_app or "",
                client_ip=client_ip,
                server_ip=server_ip,
                first_seen=now,
                last_seen=now,
            )
        iface = self.interfaces[key]
        iface.last_seen = now
        iface.message_count += 1
        if sending_app and not iface.sending_app:
            iface.sending_app = sending_app
        if receiving_app and not iface.receiving_app:
            iface.receiving_app = receiving_app
        if msg_type:
            iface.message_types.add(msg_type)
        if event_type:
            iface.trigger_events.add(event_type)
        iface.segments_seen.update(segments)
        if has_phi:
            iface.phi_segments_seen = True

    def _update_devices(
        self,
        src_ip: str,
        dst_ip: str,
        src_mac: str = "",
        dst_mac: str = "",
        sending_app: str = "",
        receiving_app: str = "",
    ) -> None:
        """Update device entries."""
        if is_valid_discovered_ip(dst_ip):
            dst_vendor = lookup_mac_vendor(dst_mac) if dst_mac else ""
            key = f"hl7-server:{dst_ip}"
            name = f"HL7 Server ({receiving_app})" if receiving_app else f"HL7 Server ({dst_ip})"
            device, is_new = self._ensure_device(
                key,
                dst_ip,
                mac=dst_mac,
                name=name,
                manufacturer=dst_vendor if dst_vendor else "",
                device_type="HL7 Interface Engine",
            )
            if is_new:
                device.hl7_passive_data = {
                    "role": "server",
                    "protocol": "HL7 v2/MLLP",
                    "application": receiving_app,
                }

        if is_valid_discovered_ip(src_ip):
            src_vendor = lookup_mac_vendor(src_mac) if src_mac else ""
            key = f"hl7-client:{src_ip}"
            name = f"HL7 Client ({sending_app})" if sending_app else f"HL7 Client ({src_ip})"
            device, is_new = self._ensure_device(
                key,
                src_ip,
                mac=src_mac,
                name=name,
                manufacturer=src_vendor if src_vendor else "",
                device_type="HL7 Application",
            )
            if is_new:
                device.hl7_passive_data = {
                    "role": "client",
                    "protocol": "HL7 v2/MLLP",
                    "application": sending_app,
                }

    def _format_protocol_columns(self, ix: ProtocolInteraction) -> List[Any]:
        d = ix.details
        msg_type = d.get("message_type", "")
        event = d.get("trigger_event", "")
        sending = d.get("sending_app", "")
        receiving = d.get("receiving_app", "")
        # Detail
        detail_parts = []
        event_name = d.get("trigger_event_name", "")
        if event_name and event_name != event:
            detail_parts.append(event_name)
        if d.get("phi_segments_present"):
            detail_parts.append("[PHI]")
        segments = d.get("segments", [])
        if segments:
            detail_parts.append(f"segs={','.join(segments[:5])}")
        detail = " ".join(detail_parts)
        return [msg_type, event, sending, receiving, detail]

    def harvest(self) -> Dict[str, Any]:
        """Return harvest with PHI exposure alerts."""
        result = super().harvest()
        alerts = result.get("alerts", [])

        for iface in self.interfaces.values():
            if iface.phi_segments_seen:
                alerts.append(
                    {
                        "level": "fail",
                        "category": "phi_exposure",
                        "message": (
                            f"HL7 PHI EXPOSURE: {iface.sending_app or iface.client_ip} -> "
                            f"{iface.receiving_app or iface.server_ip} "
                            f"({iface.client_ip} -> {iface.server_ip}) "
                            f"PHI segments in {iface.message_count} message(s)"
                        ),
                    }
                )

        # Unencrypted HL7 alert
        if self.interfaces:
            alerts.append(
                {
                    "level": "warning",
                    "category": "cleartext",
                    "message": (
                        f"HL7: {len(self.interfaces)} interface(s) observed "
                        "without TLS encryption (MLLP cleartext)"
                    ),
                }
            )

        if alerts:
            result["alerts"] = alerts
        return result

    def get_sessions_summary(self) -> List[Dict[str, Any]]:
        """Get summary of all observed HL7 interfaces."""
        return [
            {
                "sending_app": i.sending_app,
                "receiving_app": i.receiving_app,
                "client": i.client_ip,
                "server": i.server_ip,
                "message_types": sorted(i.message_types),
                "trigger_events": sorted(i.trigger_events),
                "segments": sorted(i.segments_seen),
                "message_count": i.message_count,
                "phi_exposed": i.phi_segments_seen,
                "first_seen": i.first_seen,
                "last_seen": i.last_seen,
            }
            for i in self.interfaces.values()
        ]
