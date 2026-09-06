"""
BACnet Passive Listener for building automation traffic analysis (ICS).

Passively captures BACnet/IP traffic to extract:
- Service types (ReadProperty, WriteProperty, SubscribeCOV, etc.)
- Object types and instance numbers (Analog Value 1, Binary Output 3, etc.)
- Property identifiers (present-value, status-flags, etc.)
- Values read/written
- WhoIs/IAm discovery activity
- Error/Reject/Abort responses with reason codes
- Request/response correlation via invoke IDs

BACnet (Building Automation and Control networking protocol) is the
standard for building automation and control systems, commonly used in
HVAC, lighting, fire detection, and access control.

tshark fields used:
- bacapp.type: APDU type (0=Confirmed-Request, 1=Unconfirmed-Request,
  2=SimpleAck, 3=ComplexAck, 4=SegmentAck, 5=Error, 6=Reject, 7=Abort)
- bacapp.confirmed_service: Confirmed service choice (FT_UINT8)
- bacapp.unconfirmed_service: Unconfirmed service choice (FT_UINT8)
- bacapp.objectType: Object type (FT_UINT32, upper 10 bits of the
  BACnetObjectIdentifier).  tshark does NOT emit a combined
  ``bacapp.objectIdentifier``; the composite object id and the device id
  are synthesized here from objectType + instance_number.
- bacapp.instance_number: Instance number (FT_UINT32, lower 22 bits)
- bacapp.property_identifier: Property ID (FT_UINT32)
- bacapp.invoke_id: Invoke ID for request/response correlation (FT_UINT8)
- bacapp.error_class: Error class for Error PDUs (FT_UINT32)
- bacapp.error_code: Error code for Error PDUs (FT_UINT32)
- bacapp.reject_reason: Reject reason for Reject PDUs (FT_UINT8)
- bacapp.abort_reason: Abort reason for Abort PDUs (FT_UINT8)
- bacapp.sequence_number: Sequence number for segmented transfers (FT_UINT8)
- bacapp.processId: Process identifier for subscriptions (FT_UINT32)
- bacapp.present_value.real: Present value float (FT_DOUBLE)
- bacapp.present_value.uint: Present value unsigned (FT_UINT64)
- bacapp.present_value.boolean: Present value bool (FT_BOOLEAN)
- bacapp.present_value.enum_index: Present value enum (FT_UINT32)
- bacapp.vendor_identifier: Vendor ID (FT_UINT16)
- bacapp.object_name: Object name (FT_STRING)
- bacapp.who_is.low_limit: WhoIs low limit (FT_UINT32)
- bacapp.who_is.high_limit: WhoIs high limit (FT_UINT32)

References:
- ASHRAE Standard 135: BACnet
- Wireshark dissector: packet-bacapp.c
"""

import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Tuple

from .pyshark_base import ProtocolInteraction, PySharkListenerBase
from ..protocols.discovery.core import is_valid_discovered_ip, lookup_mac_vendor


# BACnet confirmed service choices
BACNET_CONFIRMED_SERVICES = {
    0: "AcknowledgeAlarm",
    1: "ConfirmedCOVNotification",
    2: "ConfirmedEventNotification",
    3: "GetAlarmSummary",
    4: "GetEnrollmentSummary",
    5: "SubscribeCOV",
    6: "AtomicReadFile",
    7: "AtomicWriteFile",
    8: "AddListElement",
    9: "RemoveListElement",
    10: "CreateObject",
    11: "DeleteObject",
    12: "ReadProperty",
    13: "ReadPropertyConditional",
    14: "ReadPropertyMultiple",
    15: "WriteProperty",
    16: "WritePropertyMultiple",
    17: "DeviceCommunicationControl",
    18: "ConfirmedPrivateTransfer",
    19: "ConfirmedTextMessage",
    20: "ReinitializeDevice",
    21: "VT-Open",
    22: "VT-Close",
    23: "VT-Data",
    24: "Authenticate",
    25: "RequestKey",
    26: "ReadRange",
    27: "LifeSafetyOperation",
    28: "SubscribeCOVProperty",
    29: "GetEventInformation",
}

# BACnet unconfirmed service choices
BACNET_UNCONFIRMED_SERVICES = {
    0: "I-Am",
    1: "I-Have",
    2: "UnconfirmedCOVNotification",
    3: "UnconfirmedEventNotification",
    4: "UnconfirmedPrivateTransfer",
    5: "UnconfirmedTextMessage",
    6: "TimeSynchronization",
    7: "Who-Has",
    8: "Who-Is",
    9: "UTCTimeSynchronization",
    10: "WriteGroup",
}

# BACnet object types (common subset)
BACNET_OBJECT_TYPES = {
    0: "AI",  # Analog Input
    1: "AO",  # Analog Output
    2: "AV",  # Analog Value
    3: "BI",  # Binary Input
    4: "BO",  # Binary Output
    5: "BV",  # Binary Value
    6: "Calendar",
    7: "Command",
    8: "Device",
    9: "EventEnrollment",
    10: "File",
    11: "Group",
    12: "Loop",
    13: "MI",  # Multi-state Input
    14: "MO",  # Multi-state Output
    15: "NotificationClass",
    16: "Program",
    17: "Schedule",
    19: "MV",  # Multi-state Value
    20: "TrendLog",
    23: "Accumulator",
    24: "PulseConverter",
}

# BACnet property identifiers (common subset)
BACNET_PROPERTIES = {
    28: "description",
    36: "event-state",
    55: "object-identifier",
    62: "object-list",
    70: "object-type",
    75: "object-name",
    77: "priority-array",
    79: "present-value",
    81: "reliability",
    85: "present-value",  # Duplicate mapping for robustness
    87: "relinquish-default",
    103: "resolution",
    104: "required",
    111: "status-flags",
    112: "system-status",
    117: "units",
    120: "vendor-identifier",
    121: "vendor-name",
    139: "protocol-version",
    168: "active-cov-subscriptions",
}

# Write/control services (security-relevant)
BACNET_WRITE_SERVICES = {7, 8, 9, 10, 11, 15, 16, 17, 20}

# BACnet error classes (ASHRAE 135-2020, Clause 18.8)
BACNET_ERROR_CLASSES = {
    0: "device",
    1: "object",
    2: "property",
    3: "resources",
    4: "security",
    5: "services",
    6: "vt",
    7: "communication",
}

# BACnet error codes (common subset, ASHRAE 135-2020, Clause 18.9)
BACNET_ERROR_CODES = {
    0: "other",
    1: "authentication-failed",
    2: "configuration-in-progress",
    3: "device-busy",
    4: "dynamic-creation-not-supported",
    7: "inconsistent-parameters",
    9: "no-objects-of-specified-type",
    14: "no-space-for-object",
    15: "no-space-to-add-list-element",
    17: "object-deletion-not-permitted",
    20: "operational-problem",
    23: "password-failure",
    25: "read-access-denied",
    26: "service-request-denied",
    28: "unknown-object",
    31: "unknown-property",
    32: "unknown-vt-class",
    36: "cov-subscription-failed",
    40: "write-access-denied",
    41: "character-set-not-supported",
    42: "invalid-data-type",
    44: "datatype-not-supported",
    46: "value-out-of-range",
    47: "duplicate-name",
    48: "duplicate-object-id",
}

# BACnet reject reasons (ASHRAE 135-2020, Clause 18.10)
BACNET_REJECT_REASONS = {
    0: "other",
    1: "buffer-overflow",
    2: "inconsistent-parameters",
    3: "invalid-parameter-data-type",
    4: "invalid-tag",
    5: "missing-required-parameter",
    6: "parameter-out-of-range",
    7: "too-many-arguments",
    8: "undefined-enumeration",
    9: "unrecognized-service",
}

# BACnet abort reasons (ASHRAE 135-2020, Clause 18.11)
BACNET_ABORT_REASONS = {
    0: "other",
    1: "buffer-overflow",
    2: "invalid-apdu-in-this-state",
    3: "preempted-by-higher-priority-task",
    4: "segmentation-not-supported",
    5: "security-error",
    6: "insufficient-security",
    7: "window-size-out-of-range",
    8: "application-exceeded-reply-time",
    9: "out-of-resources",
    10: "tsm-timeout",
    11: "apdu-too-long",
}


@dataclass
class BACnetCredential:
    """Extracted BACnet cleartext password.

    DeviceCommunicationControl (svc 17) and ReinitializeDevice (svc 20) carry an
    optional CharacterString password in the request APDU. It is sent in the
    clear, so a passive capture recovers it directly (no hash/cracking).
    """

    password: str
    service: str  # "DeviceCommunicationControl" | "ReinitializeDevice"
    client_ip: str = ""
    server_ip: str = ""
    server_port: int = 0
    timestamp: str = ""
    credential_type: str = "plaintext"

    @property
    def username(self) -> str:
        """BACnet device-management passwords have no associated username."""
        return ""

    @property
    def auth_method(self) -> str:
        return f"BACnet/{self.service}"


@dataclass
class BACnetSession:
    """Track BACnet session statistics."""

    client_ip: str
    server_ip: str
    services: Set[str] = field(default_factory=set)
    write_count: int = 0
    read_count: int = 0
    first_seen: str = ""
    last_seen: str = ""


class BACnetPassiveListener(PySharkListenerBase):
    """Passive BACnet/IP traffic listener for building automation analysis.

    Captures BACnet traffic to extract:
    - Service operations (ReadProperty, WriteProperty, etc.)
    - Object access (type, instance, property)
    - Present values read/written
    - WhoIs/IAm discovery
    - Device communication control
    """

    PROTOCOL_NAME = "bacnet"
    DISPLAY_FILTER = "bacapp"
    REQUIRED_LAYERS = ("bacapp",)
    PROTOCOL_COLUMNS = ("service", "object", "property", "value")

    def __init__(
        self,
        interface: str,
        timeout: int = 60,
        nxc_logger: Optional[Any] = None,
    ):
        super().__init__(interface, timeout, nxc_logger)
        self.sessions: Dict[Tuple[str, str], BACnetSession] = {}
        self.credentials: List[BACnetCredential] = []
        self._seen_creds: Set[Tuple[str, str, str]] = set()

    def process_packet(self, packet) -> None:
        """Process BACnet packet and extract interactions."""
        if not hasattr(packet, "bacapp"):
            return

        bacapp = packet.bacapp
        src_ip, dst_ip = self.get_ip_info(packet)
        if not src_ip or not dst_ip:
            # BACnet/MSTP (LLC) packets have no IP layer; use MACs as identifiers
            src_mac, dst_mac = self.get_mac_info(packet)
            if src_mac and dst_mac:
                src_ip = f"MAC:{src_mac}"
                dst_ip = f"MAC:{dst_mac}"
            else:
                return

        flow_id = self.get_flow_id(packet)

        # Get MAC addresses for vendor lookup
        src_mac, dst_mac = self.get_mac_info(packet)

        now = datetime.now().isoformat()

        # Get APDU type
        apdu_type_raw = self.get_field(bacapp, "type", None)
        apdu_type = None
        if apdu_type_raw is not None:
            try:
                apdu_type = int(apdu_type_raw)
            except (ValueError, TypeError) as e:
                self.logger.debug(f"Failed to get apdu_type: {e}")

        if apdu_type is None:
            return

        # Extract invoke_id for request/response correlation
        invoke_id_raw = self.get_field(bacapp, "invoke_id", None)
        invoke_id = None
        if invoke_id_raw is not None:
            try:
                invoke_id = int(invoke_id_raw)
            except (ValueError, TypeError) as e:
                self.logger.debug(f"Failed to get invoke_id: {e}")

        # Determine service
        svc_name = ""
        svc_code = None

        if apdu_type == 0:  # Confirmed Request
            svc_raw = self.get_field(bacapp, "confirmed_service", None)
            if svc_raw is not None:
                try:
                    svc_code = int(svc_raw)
                    svc_name = BACNET_CONFIRMED_SERVICES.get(svc_code, f"ConfirmedSvc {svc_code}")
                except (ValueError, TypeError) as e:
                    self.logger.debug(f"Failed to get svc_code: {e}")
            direction = "request"
        elif apdu_type == 1:  # Unconfirmed Request
            svc_raw = self.get_field(bacapp, "unconfirmed_service", None)
            if svc_raw is not None:
                try:
                    svc_code = int(svc_raw)
                    svc_name = BACNET_UNCONFIRMED_SERVICES.get(
                        svc_code, f"UnconfirmedSvc {svc_code}"
                    )
                except (ValueError, TypeError) as e:
                    self.logger.debug(f"Failed to get svc_code: {e}")
            direction = "request"
        elif apdu_type == 2:  # SimpleAck
            direction = "response"
            svc_name = "SimpleAck"
        elif apdu_type == 3:  # ComplexAck
            svc_raw = self.get_field(bacapp, "confirmed_service", None)
            if svc_raw is not None:
                try:
                    svc_code = int(svc_raw)
                    svc_name = BACNET_CONFIRMED_SERVICES.get(svc_code, f"ConfirmedSvc {svc_code}")
                except (ValueError, TypeError) as e:
                    self.logger.debug(f"Failed to get svc_code: {e}")
            direction = "response"
        elif apdu_type == 5:  # Error
            direction = "response"
            # Error PDUs also carry confirmed_service to identify what failed
            svc_raw = self.get_field(bacapp, "confirmed_service", None)
            if svc_raw is not None:
                try:
                    svc_code = int(svc_raw)
                except (ValueError, TypeError) as e:
                    self.logger.debug(f"Failed to get svc_code: {e}")
            svc_name = "Error"
        elif apdu_type == 6:  # Reject
            direction = "response"
            svc_name = "Reject"
        elif apdu_type == 4:  # SegmentAck
            direction = "response"
            svc_name = "SegmentAck"
        elif apdu_type == 7:  # Abort
            direction = "response"
            svc_name = "Abort"
        else:
            direction = "request"
            svc_name = f"APDU-{apdu_type}"

        if not svc_name:
            # Service choice absent (e.g. ComplexAck/segmented PDUs where the
            # choice lives on the matching request). Don't silently drop the
            # packet: record a generic interaction so every bacapp packet
            # yields at least one row, matching the modbus/iec104/mms/s7comm
            # catch-all pattern.
            svc_name = f"APDU-{apdu_type}"
            self.logger.debug(
                f"BACnet: no service choice for apdu_type={apdu_type}, recording generic {svc_name}"
            )

        # DeviceCommunicationControl (17) / ReinitializeDevice (20) carry an
        # optional cleartext password in the request APDU -- extract it.
        if direction == "request" and svc_code in (17, 20):
            self._extract_password(bacapp, svc_code, src_ip, dst_ip, packet)

        # Extract object type and instance
        obj_type_raw = self.get_field(bacapp, "objectType", None)
        inst_raw = self.get_field(bacapp, "instance_number", None)
        prop_raw = self.get_field(bacapp, "property_identifier", None)

        obj_type = None
        instance = None
        prop_id = None

        if obj_type_raw is not None:
            try:
                obj_type = int(obj_type_raw)
            except (ValueError, TypeError) as e:
                self.logger.debug(f"Failed to get obj_type: {e}")
        if inst_raw is not None:
            try:
                instance = int(inst_raw)
            except (ValueError, TypeError) as e:
                self.logger.debug(f"Failed to get instance: {e}")
        if prop_raw is not None:
            try:
                prop_id = int(prop_raw)
            except (ValueError, TypeError) as e:
                self.logger.debug(f"Failed to get prop_id: {e}")

        obj_type_name = (
            BACNET_OBJECT_TYPES.get(obj_type, f"Type{obj_type}") if obj_type is not None else ""
        )
        prop_name = BACNET_PROPERTIES.get(prop_id, f"prop{prop_id}") if prop_id is not None else ""

        # Extract present value (try multiple formats)
        present_value = None
        for pv_field in (
            "present_value_real",
            "present_value.real",
            "present_value_uint",
            "present_value.uint",
            "present_value_boolean",
            "present_value.boolean",
            "present_value_enum_index",
            "present_value.enum_index",
            "present_value_char_string",
            "present_value.char_string",
        ):
            val = self.get_field(bacapp, pv_field, None)
            if val is not None:
                present_value = str(val)
                break

        # Extract object name
        obj_name = str(self.get_field(bacapp, "object_name", "") or "").strip()

        # Extract vendor info
        vendor_id_raw = self.get_field(bacapp, "vendor_identifier", None)
        vendor_id = None
        if vendor_id_raw is not None:
            try:
                vendor_id = int(vendor_id_raw)
            except (ValueError, TypeError) as e:
                self.logger.debug(f"Failed to get vendor_id: {e}")

        # WhoIs limits
        who_is_low = self.get_field(bacapp, "who_is_low_limit", None)
        if who_is_low is None:
            who_is_low = self.get_field(bacapp, "who_is.low_limit", None)
        who_is_high = self.get_field(bacapp, "who_is_high_limit", None)
        if who_is_high is None:
            who_is_high = self.get_field(bacapp, "who_is.high_limit", None)

        # Synthesize the combined objectIdentifier.
        #
        # tshark (4.4.x) does NOT emit a ``bacapp.objectIdentifier`` field: the
        # 32-bit BACnetObjectIdentifier is dissected into ``bacapp.objectType``
        # (top 10 bits, mask 0xffc00000) and ``bacapp.instance_number`` (low 22
        # bits, mask 0x3fffff).  Reconstruct the composite per ASHRAE 135 so
        # downstream consumers get the single canonical object id.
        obj_identifier = None
        if obj_type is not None and instance is not None:
            obj_identifier = ((obj_type & 0x3FF) << 22) | (instance & 0x3FFFFF)

        # Extract error/reject/abort details
        error_class = None
        error_code = None
        reject_reason = None
        abort_reason = None

        if apdu_type == 5:  # Error
            ec_raw = self.get_field(bacapp, "error_class", None)
            if ec_raw is not None:
                try:
                    error_class = int(ec_raw)
                except (ValueError, TypeError) as e:
                    self.logger.debug(f"Failed to get error_class: {e}")
            ecode_raw = self.get_field(bacapp, "error_code", None)
            if ecode_raw is not None:
                try:
                    error_code = int(ecode_raw)
                except (ValueError, TypeError) as e:
                    self.logger.debug(f"Failed to get error_code: {e}")
        elif apdu_type == 6:  # Reject
            rr_raw = self.get_field(bacapp, "reject_reason", None)
            if rr_raw is not None:
                try:
                    reject_reason = int(rr_raw)
                except (ValueError, TypeError) as e:
                    self.logger.debug(f"Failed to get reject_reason: {e}")
        elif apdu_type == 7:  # Abort
            ar_raw = self.get_field(bacapp, "abort_reason", None)
            if ar_raw is not None:
                try:
                    abort_reason = int(ar_raw)
                except (ValueError, TypeError) as e:
                    self.logger.debug(f"Failed to get abort_reason: {e}")

        # Extract sequence number (segmented transfers)
        seq_num_raw = self.get_field(bacapp, "sequence_number", None)
        seq_num = None
        if seq_num_raw is not None:
            try:
                seq_num = int(seq_num_raw)
            except (ValueError, TypeError) as e:
                self.logger.debug(f"Failed to get seq_num: {e}")

        # Synthesize the device identifier.
        #
        # As with objectIdentifier, tshark emits no ``bacapp.deviceIdentifier``
        # field.  A BACnet device identity is just an objectIdentifier whose
        # object type is Device (8).  When this packet references a Device
        # object, expose its composite id as the device_identifier so device
        # enrichment can key on it.
        device_identifier = None
        if obj_type == 8 and instance is not None:
            device_identifier = (8 << 22) | (instance & 0x3FFFFF)

        # Extract process identifier (subscriptions/notifications)
        proc_id_raw = self.get_field(bacapp, "processId", None)
        process_id = None
        if proc_id_raw is not None:
            try:
                process_id = int(proc_id_raw)
            except (ValueError, TypeError) as e:
                self.logger.debug(f"Failed to get process_id: {e}")

        # Build details
        details: Dict[str, Any] = {"service": svc_name}

        if invoke_id is not None:
            details["invoke_id"] = invoke_id
        if obj_identifier is not None:
            details["object_identifier"] = obj_identifier
        if obj_type is not None:
            details["object_type"] = obj_type
            details["object_type_name"] = obj_type_name
        if instance is not None:
            details["instance"] = instance
        if prop_id is not None:
            details["property_id"] = prop_id
            details["property_name"] = prop_name
        if present_value is not None:
            details["present_value"] = present_value
        if obj_name:
            details["object_name"] = obj_name
        if vendor_id is not None:
            details["vendor_id"] = vendor_id
        if who_is_low is not None:
            details["who_is_low"] = str(who_is_low)
        if who_is_high is not None:
            details["who_is_high"] = str(who_is_high)
        if error_class is not None:
            details["error_class"] = error_class
            details["error_class_name"] = BACNET_ERROR_CLASSES.get(
                error_class, f"class-{error_class}"
            )
        if error_code is not None:
            details["error_code"] = error_code
            details["error_code_name"] = BACNET_ERROR_CODES.get(error_code, f"code-{error_code}")
        if reject_reason is not None:
            details["reject_reason"] = reject_reason
            details["reject_reason_name"] = BACNET_REJECT_REASONS.get(
                reject_reason, f"reason-{reject_reason}"
            )
        if abort_reason is not None:
            details["abort_reason"] = abort_reason
            details["abort_reason_name"] = BACNET_ABORT_REASONS.get(
                abort_reason, f"reason-{abort_reason}"
            )
        if seq_num is not None:
            details["sequence_number"] = seq_num
        if device_identifier is not None:
            details["device_identifier"] = device_identifier
        if process_id is not None:
            details["process_id"] = process_id

        # Build summary
        summary = self._build_summary(
            svc_name,
            svc_code,
            obj_type_name,
            instance,
            prop_name,
            present_value,
            who_is_low,
            who_is_high,
            apdu_type,
            error_class=error_class,
            error_code=error_code,
            reject_reason=reject_reason,
            abort_reason=abort_reason,
        )

        src_port, dst_port = self.get_port_info(packet)
        self._record_interaction(
            now,
            src_ip,
            dst_ip,
            direction,
            svc_name,
            details,
            summary,
            flow_id=flow_id,
            src_port=src_port,
            dst_port=dst_port,
            stream_id=self.get_stream_id(packet),
        )

        # Update session tracking (normalize direction so responses update the same session)
        if svc_name:
            if direction == "request":
                client_ip, server_ip = src_ip, dst_ip
            else:
                # Response: src is server, dst is client
                client_ip, server_ip = dst_ip, src_ip
            session_key = (client_ip, server_ip)
            if session_key not in self.sessions:
                self.sessions[session_key] = BACnetSession(
                    client_ip=client_ip,
                    server_ip=server_ip,
                    first_seen=now,
                    last_seen=now,
                )
            session = self.sessions[session_key]
            session.last_seen = now
            session.services.add(svc_name)
            if direction == "request":
                if svc_code is not None and svc_code in BACNET_WRITE_SERVICES:
                    session.write_count += 1
                else:
                    session.read_count += 1

        # Update devices
        self._update_devices(
            src_ip,
            dst_ip,
            direction,
            vendor_id,
            src_mac,
            dst_mac,
            device_identifier=device_identifier,
        )

    # tshark dissects the DCC/Reinit password as an UNNAMED field, but its
    # human-readable form survives in the bacapp ``text`` field as e.g.
    # "Password: UTF-8 'secret'". Pull the quoted value out of there.
    _PW_RE = re.compile(r"Password:[^']*'(.*)'\s*$")

    def _extract_password(self, bacapp, svc_code, src_ip, dst_ip, packet) -> None:
        """Extract the cleartext DCC/ReinitializeDevice password from the APDU."""
        raw = getattr(bacapp, "text", None)
        if isinstance(raw, (list, tuple)):
            items = [str(x) for x in raw]
        elif raw is not None:
            items = [str(raw)]
        else:
            joined = self.get_field(bacapp, "text", "")
            items = str(joined).split(",") if joined else []

        password = None
        for item in items:
            m = self._PW_RE.search(item)
            if m:
                password = m.group(1)
                break
        if not password:
            return

        service = "ReinitializeDevice" if svc_code == 20 else "DeviceCommunicationControl"
        key = (service, password, dst_ip)
        if key in self._seen_creds:
            return
        self._seen_creds.add(key)
        _, dst_port = self.get_port_info(packet)
        self.credentials.append(
            BACnetCredential(
                password=password,
                service=service,
                client_ip=src_ip,
                server_ip=dst_ip,
                server_port=dst_port or 47808,
                timestamp=datetime.now().isoformat(),
            )
        )
        self.logger.info(
            f"BACnet {service} password from {src_ip} -> {dst_ip}: '{password}'"
        )

    def get_credentials_summary(self) -> List[Dict[str, Any]]:
        """Cleartext BACnet device-management passwords (DCC / ReinitializeDevice)."""
        return [
            {
                "protocol": "BACnet",
                "credential_type": "plaintext",
                "auth_method": c.auth_method,
                "username": "",
                "password": c.password,
                "server_ip": c.server_ip,
                "client_ip": c.client_ip,
                "server_port": c.server_port,
                "timestamp": c.timestamp,
            }
            for c in self.credentials
        ]

    @staticmethod
    def _build_summary(
        svc_name: str,
        svc_code: Optional[int],
        obj_type_name: str,
        instance: Optional[int],
        prop_name: str,
        present_value: Optional[str],
        who_is_low: Optional[Any],
        who_is_high: Optional[Any],
        apdu_type: Optional[int],
        *,
        error_class: Optional[int] = None,
        error_code: Optional[int] = None,
        reject_reason: Optional[int] = None,
        abort_reason: Optional[int] = None,
    ) -> str:
        """Build human-readable summary."""
        # WhoIs/IAm
        if svc_name == "Who-Is":
            if who_is_low is not None and who_is_high is not None:
                return f"Who-Is {who_is_low}-{who_is_high}"
            return "Who-Is (broadcast)"
        if svc_name == "I-Am":
            if obj_type_name and instance is not None:
                return f"I-Am {obj_type_name}:{instance}"
            return "I-Am"

        # Error response with class/code
        if apdu_type == 5:
            parts = ["Error"]
            if svc_code is not None:
                failed_svc = BACNET_CONFIRMED_SERVICES.get(svc_code, f"svc-{svc_code}")
                parts.append(f"({failed_svc})")
            if error_class is not None:
                ec_name = BACNET_ERROR_CLASSES.get(error_class, f"class-{error_class}")
                parts.append(ec_name)
            if error_code is not None:
                ecode_name = BACNET_ERROR_CODES.get(error_code, f"code-{error_code}")
                parts.append(ecode_name)
            return " ".join(parts)

        # Reject response
        if apdu_type == 6:
            if reject_reason is not None:
                rr_name = BACNET_REJECT_REASONS.get(reject_reason, f"reason-{reject_reason}")
                return f"Reject {rr_name}"
            return "Reject"

        # Abort response
        if apdu_type == 7:
            if abort_reason is not None:
                ar_name = BACNET_ABORT_REASONS.get(abort_reason, f"reason-{abort_reason}")
                return f"Abort {ar_name}"
            return "Abort"

        # Property operations
        if obj_type_name and instance is not None:
            obj_ref = f"{obj_type_name}:{instance}"
            parts = [svc_name, obj_ref]
            if prop_name:
                parts.append(prop_name)
            if present_value is not None:
                parts.append(f"= {present_value}")
            return " ".join(parts)

        return svc_name

    def _update_devices(
        self,
        src_ip: str,
        dst_ip: str,
        direction: str,
        vendor_id: Optional[int],
        src_mac: str = "",
        dst_mac: str = "",
        device_identifier: Optional[int] = None,
    ) -> None:
        """Update device entries."""
        for ip, mac in ((src_ip, src_mac), (dst_ip, dst_mac)):
            if not is_valid_discovered_ip(ip):
                continue
            mac_vendor = lookup_mac_vendor(mac) if mac else ""
            key = f"bacnet:{ip}"
            device, is_new = self._ensure_device(
                key,
                ip,
                mac=mac,
                name=f"BACnet Device ({ip})",
                manufacturer=mac_vendor if mac_vendor else "",
                device_type="BACnet Device",
            )
            if is_new:
                proto_data: Dict[str, Any] = {"protocol": "BACnet/IP"}
                if vendor_id is not None:
                    proto_data["vendor_id"] = vendor_id
                if device_identifier is not None:
                    proto_data["device_identifier"] = device_identifier
                device.bacnet_passive_data = proto_data
            elif hasattr(device, "bacnet_passive_data") and device.bacnet_passive_data:
                # Enrich existing device with new info
                if vendor_id is not None and "vendor_id" not in device.bacnet_passive_data:
                    device.bacnet_passive_data["vendor_id"] = vendor_id
                if (
                    device_identifier is not None
                    and "device_identifier" not in device.bacnet_passive_data
                ):
                    device.bacnet_passive_data["device_identifier"] = device_identifier

    def _format_protocol_columns(self, ix: ProtocolInteraction) -> List[Any]:
        d = ix.details
        obj_type_name = d.get("object_type_name", "")
        instance = d.get("instance")
        prop_name = d.get("property_name", "")
        value = d.get("present_value", "")
        obj_str = f"{obj_type_name}:{instance}" if obj_type_name and instance is not None else ""

        # For error/reject/abort, show the reason in the Value column
        if not value:
            if "error_class_name" in d:
                value = f"{d['error_class_name']}/{d.get('error_code_name', '?')}"
            elif "reject_reason_name" in d:
                value = d["reject_reason_name"]
            elif "abort_reason_name" in d:
                value = d["abort_reason_name"]

        return [ix.operation, obj_str, prop_name, value if value else ""]

    def get_write_operations(self) -> List[Dict[str, Any]]:
        """Get sessions with write operations."""
        return [
            {
                "client": s.client_ip,
                "server": s.server_ip,
                "write_count": s.write_count,
            }
            for s in self.sessions.values()
            if s.write_count > 0
        ]

    def get_sessions_summary(self) -> List[Dict[str, Any]]:
        """Get summary of all observed BACnet sessions."""
        return [
            {
                "client": s.client_ip,
                "server": s.server_ip,
                "services": sorted(s.services),
                "read_count": s.read_count,
                "write_count": s.write_count,
            }
            for s in self.sessions.values()
        ]

    def get_control_operations(self) -> List[Dict[str, Any]]:
        """Get sessions with write/control operations."""
        return [
            {
                "controlling": s.client_ip,
                "controlled": s.server_ip,
                "control_count": s.write_count,
                "control_services": [
                    svc
                    for svc in s.services
                    if svc in {BACNET_CONFIRMED_SERVICES.get(c, "") for c in BACNET_WRITE_SERVICES}
                ],
            }
            for s in self.sessions.values()
            if s.write_count > 0
        ]
