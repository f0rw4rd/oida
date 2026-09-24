"""
MMS/ACSE Passive Listener for IEC 61850 traffic analysis (ICS).

Passively captures MMS (Manufacturing Message Specification) traffic to extract:
- ACSE authentication data (passwords, mechanism names)
- MMS service operations (Read, Write, GetNameList, etc.)
- Named variable access (IEC 61850 data model references)
- Report control block activity
- Domain download/upload operations

MMS is the application protocol used by IEC 61850 for power utility automation.
ACSE (Association Control Service Element) handles connection setup with
optional authentication.

tshark fields used:
- mms.confirmedServiceRequest: Service request type (FT_UINT32)
- mms.confirmedServiceResponse: Service response type (FT_UINT32)
- mms.invokeID: Request/response correlation ID (FT_INT32)
- mms.domainId: Domain identifier (FT_STRING)
- mms.objectName_domain_specific_itemId: Item ID within domain (FT_STRING)
- mms.vmd_specific: VMD-specific object name (FT_STRING)
- mms.domainSpecific: Domain-specific scope identifier (FT_STRING)
- mms.Identifier: Identifier list in getNameList response (FT_STRING)
- mms.errorClass: Error classification for failed operations (FT_UINT32)
- mms.failure: DataAccessError code in read responses (FT_INT32)
- mms.unconfirmedService: Unconfirmed service type (FT_UINT32)
- mms.servicesSupportedCalling: Client capability bitmask (FT_BYTES)
- mms.servicesSupportedCalled: Server capability bitmask (FT_BYTES)
- mms.getVariableAccessAttributes: Request type selector (FT_UINT32)
- mms.getNamedVariableListAttributes: Request ObjectName selector (FT_UINT32)
- mms.extendedObjectClass: Extended object class in getNameList (FT_UINT32)
- mms.iec61850.rptid: Report ID (FT_STRING)
- mms.iec61850.datset: Dataset reference (FT_STRING)
- mms.iec61850.ctlval: Control value (FT_BOOLEAN)
- acse.charstring: Authentication password (FT_STRING)
- acse.mechanism_name: Authentication mechanism OID (FT_OID)
- acse.calling_authentication_value: Calling auth selector (FT_UINT32)
- acse.responding_authentication_value: Responding auth selector (FT_UINT32)
- acse.result: Association accept/reject result (FT_UINT32)
- acse.result_source_diagnostic: Diagnostic for association result (FT_UINT32)

References:
- IEC 61850: Communication networks and systems for power utility automation
- ISO 8650: ACSE protocol specification
- Wireshark dissectors: packet-acse.c, packet-mms.c
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from oida.pcap.pyshark_base import ProtocolInteraction, PySharkListenerBase
from oida.protocols.discovery.core import is_valid_discovered_ip, lookup_mac_vendor

# MMS confirmed service request types (from ASN.1 CHOICE index)
MMS_SERVICES = {
    0: "status",
    1: "getNameList",
    2: "identify",
    3: "rename",
    4: "read",
    5: "write",
    6: "getVariableAccessAttributes",
    7: "defineNamedVariable",
    8: "defineScatteredAccess",
    9: "getScatteredAccessAttributes",
    10: "deleteVariableAccess",
    11: "defineNamedVariableList",
    12: "getNamedVariableListAttributes",
    13: "deleteNamedVariableList",
    14: "defineNamedType",
    15: "getNamedTypeAttributes",
    16: "deleteNamedType",
    17: "input",
    18: "output",
    19: "takeControl",
    20: "relinquishControl",
    21: "defineSemaphore",
    22: "deleteSemaphore",
    23: "reportSemaphoreStatus",
    24: "reportPoolSemaphoreStatus",
    25: "reportSemaphoreEntryStatus",
    26: "initiateDownloadSequence",
    27: "downloadSegment",
    28: "terminateDownloadSequence",
    29: "initiateUploadSequence",
    30: "uploadSegment",
    31: "terminateUploadSequence",
    32: "requestDomainDownload",
    33: "requestDomainUpload",
    34: "loadDomainContent",
    35: "storeDomainContent",
    36: "deleteDomain",
    37: "getDomainAttributes",
    38: "createProgramInvocation",
    39: "deleteProgramInvocation",
    40: "start",
    41: "stop",
    42: "resume",
    43: "reset",
    44: "kill",
    45: "defineEventCondition",
    46: "obtainFile",
    63: "getAlarmSummary",
    72: "fileOpen",
    73: "fileRead",
    74: "fileClose",
    75: "fileRename",
    76: "fileDelete",
    77: "fileDirectory",
}

# Write/control services (security-relevant)
# Includes: write(5), defineNamedVariable(7), download(26-28), upload(29-31),
# domain ops(32-36), program ops(38-44), obtainFile(46)
MMS_WRITE_SERVICES = {
    5,
    7,
    26,
    27,
    28,
    29,
    30,
    31,
    32,
    33,
    34,
    35,
    36,
    38,
    39,
    40,
    41,
    42,
    43,
    44,
    46,
}

# MMS error class names (from ASN.1 CHOICE index in ServiceError.errorClass)
MMS_ERROR_CLASSES = {
    0: "vmd-state",
    1: "application-reference",
    2: "definition",
    3: "resource",
    4: "service",
    5: "service-preempt",
    6: "time-resolution",
    7: "access",
    8: "initiate",
    9: "conclude",
    10: "cancel",
    11: "file",
    12: "others",
}

# MMS unconfirmed service types (from ASN.1 CHOICE index)
MMS_UNCONFIRMED_SERVICES = {
    0: "informationReport",
    1: "unsolicitedStatus",
    2: "eventNotification",
}

# ACSE association result codes
ACSE_RESULTS = {
    0: "accepted",
    1: "rejected-permanent",
    2: "rejected-transient",
}


@dataclass
class MMSCredential:
    """Extracted MMS/ACSE authentication credential."""

    auth_value: str
    auth_direction: str  # "calling" or "responding"
    credential_type: str = "plaintext"  # canonical: plaintext/hash/community
    mechanism_name: str = ""
    server_ip: str = ""
    client_ip: str = ""
    timestamp: str = ""

    @property
    def username(self) -> str:
        """Canonical scanner field alias for auth_value."""
        return self.auth_value

    @property
    def password(self) -> str:
        """Canonical scanner field."""
        return self.auth_value

    @property
    def auth_method(self) -> str:
        """Canonical scanner field."""
        return f"ACSE-{self.auth_direction}" + (
            f" ({self.mechanism_name})" if self.mechanism_name else ""
        )


class MMSPassiveListener(PySharkListenerBase):
    """Passive MMS/ACSE traffic listener for IEC 61850 analysis.

    Captures MMS traffic to extract:
    - ACSE authentication values from association setup
    - MMS service operations (read, write, control)
    - Named variable references (IEC 61850 data model)
    - Report control block activity
    - Domain upload/download
    """

    PROTOCOL_NAME = "mms"
    DISPLAY_FILTER = "acse or mms"
    REQUIRED_LAYERS = ("mms", "acse")
    SERVER_PORTS = (102,)
    PROTOCOL_COLUMNS = ("operation", "variable", "domain", "data")

    def __init__(
        self,
        interface: str,
        timeout: int = 60,
        nxc_logger: Optional[Any] = None,
    ):
        super().__init__(interface, timeout, nxc_logger)
        self.credentials: List[MMSCredential] = []

    def process_packet(self, packet) -> None:
        """Process MMS/ACSE packet and extract interactions + auth data."""
        src_ip, dst_ip = self.get_ip_info(packet)
        if not src_ip or not dst_ip:
            return

        flow_id = self.get_flow_id(packet)

        src_port, dst_port = self.get_port_info(packet)

        # Get MAC addresses for vendor lookup
        src_mac, dst_mac = self.get_mac_info(packet)

        now = datetime.now().isoformat()

        # Determine direction. MMS/IEC 61850 defaults to TCP 102 but the spec
        # allows any port; substations sometimes run on 10102/10106/10108 etc.
        # MMS has no clean single request/response field, so pass native=None
        # and let the known-server-port tier (SERVER_PORTS 102 ∪ --decode-as ∪
        # OVERRIDE_PREFS) plus the lower-port / first-seen heuristic decide.
        d = self.resolve_direction(
            packet,
            native=None,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            flow_id=flow_id,
        )
        is_request = d.is_request
        client_ip, server_ip = d.client_ip, d.server_ip
        client_mac, server_mac = (src_mac, dst_mac) if is_request else (dst_mac, src_mac)

        stream_id = self.get_stream_id(packet)

        # Check for ACSE layer (authentication). DISPLAY_FILTER matches "acse
        # or mms" so association setup (AARQ/AARE), which rarely carries a
        # nested mms layer, is still captured. But bare ACSE is also used by
        # unrelated OSI application-layer protocols (X.500 DAP, CMIP, ...);
        # only attribute it to MMS when there's a concrete MMS signal: an mms
        # layer in the same packet, or a known MMS server port (SERVER_PORTS
        # 102 ∪ --decode-as ∪ OVERRIDE_PREFS).
        is_likely_mms = (
            hasattr(packet, "mms")
            or src_port in self._known_server_ports
            or dst_port in self._known_server_ports
        )
        if hasattr(packet, "acse") and is_likely_mms:
            self._extract_acse_auth(
                packet.acse,
                src_ip,
                dst_ip,
                now,
                flow_id,
                src_port=src_port,
                dst_port=dst_port,
                stream_id=stream_id,
            )

        # Check for MMS layer (service operations)
        if hasattr(packet, "mms"):
            self._process_mms_service(
                packet.mms,
                src_ip,
                dst_ip,
                client_ip,
                server_ip,
                client_mac,
                server_mac,
                is_request,
                now,
                flow_id,
                src_port=src_port,
                dst_port=dst_port,
                stream_id=stream_id,
            )

    def _process_mms_service(
        self,
        mms,
        src_ip: str,
        dst_ip: str,
        client_ip: str,
        server_ip: str,
        client_mac: str,
        server_mac: str,
        is_request: bool,
        now: str,
        flow_id: str = "",
        *,
        src_port: int = 0,
        dst_port: int = 0,
        stream_id: str = "",
    ) -> None:
        """Process MMS service layer for interactions."""
        direction = "request" if is_request else "response"

        # Get service type
        svc_req_raw = self.get_field(mms, "confirmedServiceRequest", None)
        svc_resp_raw = self.get_field(mms, "confirmedServiceResponse", None)

        svc_code = None
        if svc_req_raw is not None:
            try:
                svc_code = int(svc_req_raw)
                direction = "request"
            except (ValueError, TypeError) as e:
                self.logger.debug(f"Failed to get svc_code: {e}")
        elif svc_resp_raw is not None:
            try:
                svc_code = int(svc_resp_raw)
                direction = "response"
            except (ValueError, TypeError) as e:
                self.logger.debug(f"Failed to get svc_code: {e}")

        if svc_code is None:
            # Check for confirmed error PDU
            error_class_raw = self.get_field(mms, "errorClass", None)
            if error_class_raw is not None:
                err_details: Dict[str, Any] = {}
                try:
                    ec = int(error_class_raw)
                    err_details["error_class"] = ec
                    err_details["error_class_name"] = MMS_ERROR_CLASSES.get(ec, str(ec))
                except (ValueError, TypeError):
                    err_details["error_class"] = str(error_class_raw)
                invoke_id_raw = self.get_field(mms, "invokeID", None)
                if invoke_id_raw is not None:
                    err_details["invoke_id"] = str(invoke_id_raw)
                # Extract sub-error code (access, vmd-state, etc.)
                for sub_field in (
                    "access",
                    "vmd_state",
                    "application_reference",
                    "definition",
                    "resource",
                    "service",
                    "service_preempt",
                    "file",
                    "others",
                ):
                    sub_val = self.get_field(mms, sub_field, None)
                    if sub_val is not None:
                        err_details["error_detail"] = str(sub_val)
                        break
                err_name = err_details.get("error_class_name", "unknown")
                self._record_interaction(
                    now,
                    src_ip,
                    dst_ip,
                    "response",
                    "Error",
                    err_details,
                    f"Error: {err_name}"
                    + (
                        f" ({err_details['error_detail']})" if "error_detail" in err_details else ""
                    ),
                    flow_id=flow_id,
                    src_port=src_port,
                    dst_port=dst_port,
                    stream_id=stream_id,
                )
                self._update_devices(client_ip, server_ip, client_mac, server_mac)
                return

            # Check for initiate/conclude/unconfirmed PDUs
            if self._has_layer_field(mms, "initiate_RequestPDU_element"):
                version = str(self.get_field(mms, "proposedVersionNumber", "") or "").strip()
                init_details: Dict[str, Any] = {}
                if version:
                    init_details["data"] = f"v{version}"
                # Extract client capability bitmask
                svc_calling = str(self.get_field(mms, "servicesSupportedCalling", "") or "").strip()
                if svc_calling:
                    init_details["services_supported_calling"] = svc_calling
                    # Ensure device exists before enriching
                    self._update_devices(client_ip, server_ip, client_mac, server_mac)
                    self._enrich_device_capabilities(client_ip, "client", svc_calling, mms)
                self._record_interaction(
                    now,
                    src_ip,
                    dst_ip,
                    "request",
                    "Initiate",
                    init_details,
                    "MMS Initiate Request",
                    flow_id=flow_id,
                    src_port=src_port,
                    dst_port=dst_port,
                    stream_id=stream_id,
                )
            elif self._has_layer_field(mms, "initiate_ResponsePDU_element"):
                version = str(self.get_field(mms, "negociatedVersionNumber", "") or "").strip()
                init_details = {}
                if version:
                    init_details["data"] = f"v{version}"
                # Extract server capability bitmask
                svc_called = str(self.get_field(mms, "servicesSupportedCalled", "") or "").strip()
                if svc_called:
                    init_details["services_supported_called"] = svc_called
                    # Ensure device exists before enriching
                    self._update_devices(client_ip, server_ip, client_mac, server_mac)
                    self._enrich_device_capabilities(server_ip, "server", svc_called, mms)
                self._record_interaction(
                    now,
                    src_ip,
                    dst_ip,
                    "response",
                    "Initiate",
                    init_details,
                    "MMS Initiate Response",
                    flow_id=flow_id,
                    src_port=src_port,
                    dst_port=dst_port,
                    stream_id=stream_id,
                )
            elif self._has_layer_field(mms, "conclude_RequestPDU_element"):
                self._record_interaction(
                    now,
                    src_ip,
                    dst_ip,
                    "request",
                    "Conclude",
                    {},
                    "MMS Conclude Request",
                    flow_id=flow_id,
                    src_port=src_port,
                    dst_port=dst_port,
                    stream_id=stream_id,
                )
            elif self._has_layer_field(mms, "conclude_ResponsePDU_element"):
                self._record_interaction(
                    now,
                    src_ip,
                    dst_ip,
                    "response",
                    "Conclude",
                    {},
                    "MMS Conclude Response",
                    flow_id=flow_id,
                    src_port=src_port,
                    dst_port=dst_port,
                    stream_id=stream_id,
                )
            elif self._has_layer_field(mms, "conclude_ErrorPDU_element"):
                self._record_interaction(
                    now,
                    src_ip,
                    dst_ip,
                    "response",
                    "Conclude Error",
                    {},
                    "MMS Conclude Error",
                    flow_id=flow_id,
                    src_port=src_port,
                    dst_port=dst_port,
                    stream_id=stream_id,
                )
            elif self._has_layer_field(mms, "initiate_ErrorPDU_element"):
                self._record_interaction(
                    now,
                    src_ip,
                    dst_ip,
                    "response",
                    "Initiate Error",
                    {},
                    "MMS Initiate Error",
                    flow_id=flow_id,
                    src_port=src_port,
                    dst_port=dst_port,
                    stream_id=stream_id,
                )

            # Cancel PDU: cancel_RequestPDU and cancel_ResponsePDU are
            # FT_INT32 (the invokeID being cancelled), not FT_NONE elements,
            # so use get_field() instead of _has_layer_field().
            cancel_req = self.get_field(mms, "cancel_RequestPDU", None)
            if cancel_req is not None:
                cancel_details: Dict[str, Any] = {"invoke_id": str(cancel_req)}
                self._record_interaction(
                    now,
                    src_ip,
                    dst_ip,
                    "request",
                    "Cancel",
                    cancel_details,
                    f"MMS Cancel Request (invokeID={cancel_req})",
                    flow_id=flow_id,
                    src_port=src_port,
                    dst_port=dst_port,
                    stream_id=stream_id,
                )
                self._update_devices(client_ip, server_ip, client_mac, server_mac)
                return
            cancel_resp = self.get_field(mms, "cancel_ResponsePDU", None)
            if cancel_resp is not None:
                cancel_details = {"invoke_id": str(cancel_resp)}
                self._record_interaction(
                    now,
                    src_ip,
                    dst_ip,
                    "response",
                    "Cancel",
                    cancel_details,
                    f"MMS Cancel Response (invokeID={cancel_resp})",
                    flow_id=flow_id,
                    src_port=src_port,
                    dst_port=dst_port,
                    stream_id=stream_id,
                )
                self._update_devices(client_ip, server_ip, client_mac, server_mac)
                return
            if self._has_layer_field(mms, "cancel_ErrorPDU_element"):
                self._record_interaction(
                    now,
                    src_ip,
                    dst_ip,
                    "response",
                    "Cancel Error",
                    {},
                    "MMS Cancel Error",
                    flow_id=flow_id,
                    src_port=src_port,
                    dst_port=dst_port,
                    stream_id=stream_id,
                )
                self._update_devices(client_ip, server_ip, client_mac, server_mac)
                return

            # Reject PDU
            if self._has_layer_field(mms, "rejectPDU_element"):
                reject_details: Dict[str, Any] = {}
                reject_reason = self.get_field(mms, "rejectReason", None)
                if reject_reason is not None:
                    reject_details["reject_reason"] = str(reject_reason)
                invoke_id_raw = self.get_field(mms, "invokeID", None)
                if invoke_id_raw is not None:
                    reject_details["invoke_id"] = str(invoke_id_raw)
                self._record_interaction(
                    now,
                    src_ip,
                    dst_ip,
                    "response",
                    "Reject",
                    reject_details,
                    "MMS Reject"
                    + (f" reason={reject_reason}" if reject_reason is not None else ""),
                    flow_id=flow_id,
                    src_port=src_port,
                    dst_port=dst_port,
                    stream_id=stream_id,
                )
                self._update_devices(client_ip, server_ip, client_mac, server_mac)
                return

            # Check for unconfirmed service PDU
            unconf_svc_raw = self.get_field(mms, "unconfirmedService", None)
            if unconf_svc_raw is not None:
                try:
                    unconf_code = int(unconf_svc_raw)
                except (ValueError, TypeError):
                    unconf_code = -1
                unconf_name = MMS_UNCONFIRMED_SERVICES.get(
                    unconf_code, f"unconfirmed({unconf_code})"
                )

                # Check for IEC 61850 report (unconfirmed InformationReport)
                rptid = str(self.get_field(mms, "iec61850_rptid", "") or "").strip()
                if not rptid:
                    rptid = str(self.get_field(mms, "iec61850.rptid", "") or "").strip()
                if rptid:
                    datset = str(self.get_field(mms, "iec61850_datset", "") or "").strip()
                    if not datset:
                        datset = str(self.get_field(mms, "iec61850.datset", "") or "").strip()
                    unconf_details: Dict[str, Any] = {
                        "rptid": rptid,
                        "unconfirmed_service": unconf_code,
                    }
                    if datset:
                        unconf_details["dataset"] = datset
                    self._record_interaction(
                        now,
                        src_ip,
                        dst_ip,
                        "response",
                        "InformationReport",
                        unconf_details,
                        f"Report {rptid}" + (f" dataset={datset}" if datset else ""),
                        flow_id=flow_id,
                        src_port=src_port,
                        dst_port=dst_port,
                        stream_id=stream_id,
                    )
                else:
                    # Generic unconfirmed service (not IEC 61850 report)
                    self._record_interaction(
                        now,
                        src_ip,
                        dst_ip,
                        "response",
                        unconf_name,
                        {"unconfirmed_service": unconf_code},
                        unconf_name,
                        flow_id=flow_id,
                        src_port=src_port,
                        dst_port=dst_port,
                        stream_id=stream_id,
                    )
                self._update_devices(client_ip, server_ip, client_mac, server_mac)
                return

            # Check for IEC 61850 report without unconfirmedService field
            rptid = str(self.get_field(mms, "iec61850_rptid", "") or "").strip()
            if not rptid:
                rptid = str(self.get_field(mms, "iec61850.rptid", "") or "").strip()
            if rptid:
                datset = str(self.get_field(mms, "iec61850_datset", "") or "").strip()
                if not datset:
                    datset = str(self.get_field(mms, "iec61850.datset", "") or "").strip()
                rpt_details: Dict[str, Any] = {"rptid": rptid}
                if datset:
                    rpt_details["dataset"] = datset
                self._record_interaction(
                    now,
                    src_ip,
                    dst_ip,
                    "response",
                    "InformationReport",
                    rpt_details,
                    f"Report {rptid}" + (f" dataset={datset}" if datset else ""),
                    flow_id=flow_id,
                    src_port=src_port,
                    dst_port=dst_port,
                    stream_id=stream_id,
                )
                self._update_devices(client_ip, server_ip, client_mac, server_mac)
                return

            # Fallback: confirmed request/response/error PDU with no
            # identifiable service type (e.g. empty response with only
            # invokeID).  These are valid MMS PDUs that tshark decoded but
            # lack a confirmedServiceRequest/Response CHOICE tag.
            fallback_invoke = self.get_field(mms, "invokeID", None)
            fb_details: Dict[str, Any] = {}
            if fallback_invoke is not None:
                fb_details["invoke_id"] = str(fallback_invoke)

            if self._has_layer_field(mms, "confirmed_ResponsePDU_element"):
                self._record_interaction(
                    now,
                    src_ip,
                    dst_ip,
                    "response",
                    "Confirmed Response",
                    fb_details,
                    "MMS Confirmed Response"
                    + (f" (invokeID={fallback_invoke})" if fallback_invoke is not None else ""),
                    flow_id=flow_id,
                    src_port=src_port,
                    dst_port=dst_port,
                    stream_id=stream_id,
                )
            elif self._has_layer_field(mms, "confirmed_RequestPDU_element"):
                self._record_interaction(
                    now,
                    src_ip,
                    dst_ip,
                    "request",
                    "Confirmed Request",
                    fb_details,
                    "MMS Confirmed Request"
                    + (f" (invokeID={fallback_invoke})" if fallback_invoke is not None else ""),
                    flow_id=flow_id,
                    src_port=src_port,
                    dst_port=dst_port,
                    stream_id=stream_id,
                )
            elif self._has_layer_field(mms, "confirmed_ErrorPDU_element"):
                self._record_interaction(
                    now,
                    src_ip,
                    dst_ip,
                    "response",
                    "Confirmed Error",
                    fb_details,
                    "MMS Confirmed Error"
                    + (f" (invokeID={fallback_invoke})" if fallback_invoke is not None else ""),
                    flow_id=flow_id,
                    src_port=src_port,
                    dst_port=dst_port,
                    stream_id=stream_id,
                )
            else:
                # Final catch-all: MMS layer present but no known PDU type
                # matched.  Record it so no packet is silently dropped.
                self.logger.debug(
                    f"Unrecognized MMS PDU from {src_ip} -> {dst_ip}, "
                    f"recording as generic MMS packet"
                )
                self._record_interaction(
                    now,
                    src_ip,
                    dst_ip,
                    direction,
                    "MMS PDU",
                    fb_details,
                    "MMS PDU (unrecognized type)",
                    flow_id=flow_id,
                    src_port=src_port,
                    dst_port=dst_port,
                    stream_id=stream_id,
                )
            self._update_devices(client_ip, server_ip, client_mac, server_mac)
            return

        svc_name = MMS_SERVICES.get(svc_code, f"Service {svc_code}")

        # Extract invoke ID for request/response correlation
        invoke_id_raw = self.get_field(mms, "invokeID", None)

        # Extract variable names for read/write
        domain_id = str(self.get_field(mms, "domainId", "") or "").strip()
        item_id = str(self.get_field(mms, "itemId", "") or "").strip()
        vmd_name = str(self.get_field(mms, "vmd_specific", "") or "").strip()

        details: Dict[str, Any] = {
            "service_code": svc_code,
            "service_name": svc_name,
        }

        # Add invoke ID for correlation
        if invoke_id_raw is not None:
            details["invoke_id"] = str(invoke_id_raw)

        variable = ""
        if domain_id and item_id:
            variable = f"{domain_id}/{item_id}"
            details["variable"] = variable
            details["domain"] = domain_id
            details["item"] = item_id
        elif vmd_name:
            variable = vmd_name
            details["variable"] = variable

        # Program invocation name (for start/stop/kill/reset/resume/create/delete)
        # Different MMS services use different field names for the program name
        prog_name = ""
        for pf in ("programInvocationName", "deleteProgramInvocation", "createProgramInvocation"):
            prog_name = str(self.get_field(mms, pf, "") or "").strip()
            if prog_name:
                break
        if prog_name:
            details["program"] = prog_name
            if not variable:
                variable = prog_name
                details["variable"] = variable

        # Domain name for domain-level services (getDomainAttributes, upload, download, etc.)
        # Each service stores the domain name under its own EK field name
        if not variable:
            _DOMAIN_FIELDS = (
                "getDomainAttributes",
                "domainName",
                "initiateUploadSequence",
                "initiateDownloadSequence",
                "requestDomainUpload",
                "requestDomainDownload",
                "loadDomainContent",
                "storeDomainContent",
                "deleteDomain",
            )
            for df in _DOMAIN_FIELDS:
                dn = str(self.get_field(mms, df, "") or "").strip()
                if dn:
                    variable = dn
                    details["variable"] = variable
                    details["domain"] = dn
                    break

        # Identify response: vendorName, modelName, revision
        if svc_code == 2:  # identify
            vendor = str(self.get_field(mms, "vendorName", "") or "").strip()
            model = str(self.get_field(mms, "modelName", "") or "").strip()
            rev = str(self.get_field(mms, "revision", "") or "").strip()
            id_parts = []
            if vendor:
                id_parts.append(vendor)
                details["vendor"] = vendor
            if model:
                id_parts.append(model)
                details["model"] = model
            if rev:
                id_parts.append(f"v{rev}")
                details["revision"] = rev
            if id_parts:
                details["data"] = " | ".join(id_parts)
                # Enrich server device with vendor/model
                if direction == "response":
                    self._enrich_server_identity(server_ip, vendor, model, rev)

        # getNameList: extract objectClass, domainSpecific scope, extendedObjectClass, identifiers
        if svc_code == 1:  # getNameList
            obj_class_raw = str(self.get_field(mms, "objectClass", "") or "").strip()
            _OBJ_CLASSES = {
                "0": "namedVariable",
                "1": "scatteredAccess",
                "2": "namedVariableList",
                "3": "namedType",
                "4": "semaphore",
                "5": "eventCondition",
                "6": "eventAction",
                "7": "eventEnrollment",
                "8": "journal",
                "9": "domain",
                "10": "programInvocation",
                "11": "operatorStation",
            }
            obj_class = _OBJ_CLASSES.get(obj_class_raw, obj_class_raw)
            if obj_class:
                details["object_class"] = obj_class
            # Domain-specific scope identifier
            domain_scope = str(self.get_field(mms, "domainSpecific", "") or "").strip()
            if domain_scope:
                details["domain_specific"] = domain_scope
                if not details.get("domain"):
                    details["domain"] = domain_scope
            # Extended object class
            ext_obj_class_raw = self.get_field(mms, "extendedObjectClass", None)
            if ext_obj_class_raw is not None:
                details["extended_object_class"] = str(ext_obj_class_raw)
            # For responses, extract identifier list and count
            if direction == "response":
                identifiers = self._extract_identifiers(mms)
                if identifiers:
                    details["identifiers"] = identifiers
                    details["data"] = f"{len(identifiers)} names"
                else:
                    id_count = self._count_identifiers(mms)
                    if id_count > 0:
                        details["data"] = f"{id_count} names"
                more = str(self.get_field(mms, "moreFollows", "") or "").strip()
                if more.lower() in ("true", "1"):
                    details.setdefault("data", "")
                    if details["data"]:
                        details["data"] += " (more)"
                    else:
                        details["data"] = "(more)"
            elif obj_class:
                details["data"] = f"class={obj_class}"

        # getVariableAccessAttributes: extract request type selector
        if svc_code == 6:  # getVariableAccessAttributes
            gva_raw = self.get_field(mms, "getVariableAccessAttributes", None)
            if gva_raw is not None:
                details["get_var_access_attr"] = str(gva_raw)

        # getNamedVariableListAttributes: extract request ObjectName selector
        if svc_code == 12:  # getNamedVariableListAttributes
            gnvla_raw = self.get_field(mms, "getNamedVariableListAttributes", None)
            if gnvla_raw is not None:
                details["get_named_var_list_attr"] = str(gnvla_raw)

        # Upload/download state reference (terminateUploadSequence carries an ID)
        if svc_code in (30, 31):  # uploadSegment, terminateUploadSequence
            state_id = str(self.get_field(mms, "terminateUploadSequence", "") or "").strip()
            if state_id:
                details["upload_state"] = state_id

        # Download capabilities (initiateDownloadSequence)
        if svc_code == 26:
            cap = str(self.get_field(mms, "listOfCapabilities_item", "") or "").strip()
            if cap:
                details["capabilities"] = cap
            sharable = self.get_field(mms, "sharable", None)
            if sharable is not None:
                details["sharable"] = str(sharable)

        # Semaphore name for takeControl/relinquishControl
        if svc_code in (19, 20, 21, 22, 23, 24, 25):
            sem_name = str(self.get_field(mms, "semaphoreName", "") or "").strip()
            if sem_name and not variable:
                # semaphoreName field is an enum (0=vmd, 1=domain, 2=aa)
                # the actual name comes from vmd_specific which is already captured
                pass

        # Alarm summary flags
        if svc_code == 63:  # getAlarmSummary
            active_only = self.get_field(mms, "activeAlarmsOnly", None)
            if active_only is not None:
                details["active_only"] = str(active_only)
            enroll_only = self.get_field(mms, "enrollmentsOnly", None)
            if enroll_only is not None:
                details["enrollments_only"] = str(enroll_only)

        # IEC 61850 control value
        ctlval_raw = self.get_field(mms, "iec61850_ctlval", None)
        if ctlval_raw is None:
            ctlval_raw = self.get_field(mms, "iec61850.ctlval", None)
        if ctlval_raw is not None:
            details["ctlVal"] = str(ctlval_raw)

        # Extract data values for read/write services
        if "data" not in details:
            data_value = self._extract_mms_value(mms)
            if data_value:
                details["data"] = data_value

        # DataAccessError (failure) in read responses
        failure_raw = self.get_field(mms, "failure", None)
        if failure_raw is not None:
            details["failure"] = str(failure_raw)

        # Write response success
        if svc_code == 5 and direction == "response":
            success = str(self.get_field(mms, "success", "") or "").strip()
            if success and "data" not in details:
                details["data"] = "ok"

        # Build summary
        if variable:
            summary = f"{svc_name} {variable}"
            if ctlval_raw is not None:
                summary += f" ctlVal={ctlval_raw}"
            elif details.get("data"):
                summary += f" = {details['data']}"
        else:
            summary = svc_name
            if details.get("data"):
                summary += f": {details['data']}"

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
            stream_id=stream_id,
        )

        # Update devices
        self._update_devices(client_ip, server_ip, client_mac, server_mac)

    def _extract_mms_value(self, mms) -> str:
        """Extract data value from MMS read response or write request.

        Tries typed value fields in priority order:
        - mms.boolean (FT_BOOLEAN)
        - mms.integer (FT_INT32)
        - mms.unsigned (FT_UINT32)
        - mms.floating_point (FT_BYTES -- IEEE 754 encoded)
        - mms.data.visible-string (FT_STRING)
        - mms.data.octet-string (FT_BYTES)
        - mms.data.bit-string (FT_BYTES)

        Returns a human-readable value string, or "" if no value found.
        """
        # Boolean
        val = self.get_field(mms, "boolean", None)
        if val is not None:
            return "True" if str(val) in ("True", "1") else "False"

        # Integer (signed)
        val = self.get_field(mms, "integer", None)
        if val is not None:
            return str(val)

        # Unsigned integer
        val = self.get_field(mms, "unsigned", None)
        if val is not None:
            return str(val)

        # Floating point
        val = self.get_field(mms, "floating_point", None)
        if val is not None:
            return str(val)

        # Visible string
        for fname in ("data_visible_string", "data.visible-string"):
            val = self.get_field(mms, fname, None)
            if val is not None:
                return str(val).strip()

        # Octet string
        for fname in ("data_octet_string", "data.octet-string"):
            val = self.get_field(mms, fname, None)
            if val is not None:
                return str(val).strip()

        # Bit string
        for fname in ("data_bit_string", "data.bit-string"):
            val = self.get_field(mms, fname, None)
            if val is not None:
                return str(val).strip()

        return ""

    @staticmethod
    def _has_layer_field(layer, field_name: str) -> bool:
        """Check if a field is present on the layer (works in both XML and EK mode).

        In EK mode, ASN.1 container elements (e.g. ``aarq_element``) have
        null values, so ``get_field()`` returns ``None`` even when the field
        exists.  ``has_field()`` correctly detects presence.

        In XML mode ``has_field()`` exists too but returns False for these
        zero-length ASN.1 marker elements, even though the key is present in
        ``layer._all_fields``.  The old code returned that False immediately,
        so the fallback below was unreachable and every PDU-type branch that
        keys off a ``*_element`` marker was dead on the live-capture path
        (``pyshark_base`` builds LiveCapture without ``use_ek``, i.e. XML
        mode).  Concretely: all 29 Initiate PDUs across the MMS fixtures were
        classified as generic "MMS PDU" in XML mode but correctly as
        "Initiate" in EK mode.  So treat has_field() as a positive-only
        signal and keep probing.
        """
        if hasattr(layer, "has_field"):
            try:
                if layer.has_field(field_name):
                    return True
            except (AttributeError, TypeError, KeyError):
                # pragma: no cover - defensive, pyshark internals. has_field is
                # a positive-only signal here; fall through to the _all_fields
                # and attribute-based checks below.
                pass

        # XML mode: the raw field map is keyed by the fully-qualified tshark
        # name ("mms.initiate_RequestPDU_element"), so accept either form.
        all_fields = getattr(layer, "_all_fields", None)
        if all_fields:
            if field_name in all_fields:
                return True
            suffix = "." + field_name
            if any(key.endswith(suffix) for key in all_fields):
                return True

        # Last resort: plain attribute access with a non-None value.
        return getattr(layer, field_name, None) is not None

    def _extract_identifiers(self, mms) -> List[str]:
        """Extract Identifier list from getNameList response.

        In EK mode, mms.Identifier may be a comma-separated list (from
        get_field list->str normalization) or a single string.
        Returns a list of identifier strings, or empty list if not found.
        """
        raw = self.get_field(mms, "Identifier", None)
        if raw is None:
            return []
        raw_str = str(raw).strip()
        if not raw_str:
            return []
        # EK mode list values are joined with commas by get_field()
        return [s.strip() for s in raw_str.split(",") if s.strip()]

    def _count_identifiers(self, mms) -> int:
        """Count Identifier items in getNameList response via str(layer) parsing.

        PyShark's _all_fields dict deduplicates repeated Identifier fields.
        Parse the text representation to count all occurrences.
        """
        try:
            layer_text = str(mms)
        except Exception as e:
            self.logger.debug(f"Failed to get layer_text: {e}")
            return 0
        count = 0
        for line in layer_text.split("\n"):
            stripped = line.strip()
            if stripped.startswith("Identifier:"):
                count += 1
        return count

    def _enrich_server_identity(
        self, server_ip: str, vendor: str, model: str, revision: str
    ) -> None:
        """Enrich server device with vendor/model from identify response."""
        if not is_valid_discovered_ip(server_ip):
            return
        server_key = f"mms-server:{server_ip}"
        device = self.discovered_devices.get(server_key)
        if device:
            if vendor and not device.manufacturer:
                device.manufacturer = vendor
            if model:
                device.name = f"{model} ({server_ip})"
            if not device.mms_passive_data:
                device.mms_passive_data = {"role": "server", "protocol": "MMS/TCP"}
            device.mms_passive_data["vendor"] = vendor
            device.mms_passive_data["model"] = model
            device.mms_passive_data["revision"] = revision

    def _enrich_device_capabilities(self, ip: str, role: str, svc_bitmask: str, mms: Any) -> None:
        """Enrich device with MMS supported services from Initiate PDU.

        Parses the ServiceSupportOptions boolean fields to build a list of
        supported service names, stored in the device's mms_passive_data.
        """
        if not is_valid_discovered_ip(ip):
            return
        device_key = f"mms-{role}:{ip}"
        device = self.discovered_devices.get(device_key)
        if not device:
            return
        if not device.mms_passive_data:
            device.mms_passive_data = {"role": role, "protocol": "MMS/TCP"}
        device.mms_passive_data["services_bitmask"] = svc_bitmask
        # Extract supported service names from boolean fields
        supported = []
        for svc_name in sorted(MMS_SERVICES.values()):
            field = f"ServiceSupportOptions_{svc_name}"
            val = self.get_field(mms, field, None)
            if val is not None and str(val).lower() in ("true", "1"):
                supported.append(svc_name)
        if supported:
            device.mms_passive_data["services_supported"] = supported

    def _extract_acse_auth(
        self,
        acse,
        src_ip: str,
        dst_ip: str,
        now: str,
        flow_id: str = "",
        *,
        src_port: int = 0,
        dst_port: int = 0,
        stream_id: str = "",
    ) -> None:
        """Extract authentication values from ACSE layer."""
        auth_value = str(self.get_field(acse, "charstring", "") or "").strip()

        if not auth_value:
            auth_value = str(self.get_field(acse, "bitstring", "") or "").strip()

        mechanism = str(self.get_field(acse, "mechanism_name", "") or "").strip()

        # Determine direction from CHOICE selector presence
        calling_selector = self.get_field(acse, "calling_authentication_value", None)
        responding_selector = self.get_field(acse, "responding_authentication_value", None)

        # Record ACSE association setup as interaction
        # EK mode stores element containers as null-valued EkMultiField objects,
        # so get_field() returns None.  Use has_field() for presence detection.
        if self._has_layer_field(acse, "aarq_element"):
            aarq_details: Dict[str, Any] = {"has_auth": bool(auth_value)}
            # ACSE protocol version advertised by the calling AE (FT_BYTES bitstring).
            # tshark exposes both AARQ and AARE versions under the shared
            # acse.protocol_version token (EK key acse_acse_protocol_version).
            aarq_ver = str(self.get_field(acse, "protocol_version", "") or "").strip()
            if aarq_ver:
                aarq_details["acse_protocol_version"] = aarq_ver
            self._record_interaction(
                now,
                src_ip,
                dst_ip,
                "request",
                "ACSE Associate",
                aarq_details,
                "ACSE AARQ" + (" (authenticated)" if auth_value else ""),
                flow_id=flow_id,
                src_port=src_port,
                dst_port=dst_port,
                stream_id=stream_id,
            )
        elif self._has_layer_field(acse, "aare_element"):
            aare_details: Dict[str, Any] = {"has_auth": bool(auth_value)}
            # ACSE protocol version advertised by the responding AE (FT_BYTES bitstring).
            # Shared token acse.protocol_version (EK key acse_acse_protocol_version)
            # covers both AARQ and AARE; the surrounding element selects direction.
            aare_ver = str(self.get_field(acse, "protocol_version", "") or "").strip()
            if aare_ver:
                aare_details["acse_protocol_version"] = aare_ver
            # Extract association result code
            result_raw = self.get_field(acse, "result", None)
            if result_raw is not None:
                try:
                    result_code = int(result_raw)
                except (ValueError, TypeError):
                    result_code = -1
                aare_details["result"] = result_code
                aare_details["result_name"] = ACSE_RESULTS.get(result_code, str(result_raw))
            # Extract result source diagnostic
            diag_raw = self.get_field(acse, "result_source_diagnostic", None)
            if diag_raw is not None:
                aare_details["result_source_diagnostic"] = str(diag_raw)
            # Extract service_user diagnostic
            svc_user_raw = self.get_field(acse, "service_user", None)
            if svc_user_raw is not None:
                aare_details["service_user"] = str(svc_user_raw)
            result_name = aare_details.get("result_name", "")
            summary_suffix = ""
            if result_name and result_name != "accepted":
                summary_suffix = f" [{result_name}]"
            self._record_interaction(
                now,
                src_ip,
                dst_ip,
                "response",
                "ACSE Associate",
                aare_details,
                "ACSE AARE" + (" (authenticated)" if auth_value else "") + summary_suffix,
                flow_id=flow_id,
                src_port=src_port,
                dst_port=dst_port,
                stream_id=stream_id,
            )
        elif self._has_layer_field(acse, "rlrq_element"):
            self._record_interaction(
                now,
                src_ip,
                dst_ip,
                "request",
                "ACSE Release",
                {},
                "ACSE Release Request",
                flow_id=flow_id,
                src_port=src_port,
                dst_port=dst_port,
                stream_id=stream_id,
            )

        if not auth_value:
            return

        if calling_selector is not None:
            if not self._is_duplicate(auth_value, "calling", src_ip, dst_ip):
                cred = MMSCredential(
                    auth_value=auth_value,
                    auth_direction="calling",
                    credential_type="plaintext",
                    mechanism_name=mechanism,
                    server_ip=dst_ip,
                    client_ip=src_ip,
                    timestamp=now,
                )
                self.credentials.append(cred)
                self._update_devices(src_ip, dst_ip)
                self.logger.info(f"MMS/ACSE: calling auth value from {src_ip} to {dst_ip}")

        if responding_selector is not None:
            # The responding branch stores the credential from the *server's*
            # point of view (client_ip=dst_ip, server_ip=src_ip), so the
            # duplicate lookup -- which compares client_ip against its third
            # argument -- has to be given the same orientation.  Passing
            # (src_ip, dst_ip) here meant the key could never match anything
            # this branch had stored, and the same credential was re-appended
            # for every responding packet in the association.
            if not self._is_duplicate(auth_value, "responding", dst_ip, src_ip):
                cred = MMSCredential(
                    auth_value=auth_value,
                    auth_direction="responding",
                    credential_type="plaintext",
                    mechanism_name=mechanism,
                    server_ip=src_ip,
                    client_ip=dst_ip,
                    timestamp=now,
                )
                self.credentials.append(cred)
                self._update_devices(dst_ip, src_ip)
                self.logger.info(f"MMS/ACSE: responding auth value from {src_ip} to {dst_ip}")

    def _is_duplicate(self, auth_value: str, direction: str, src_ip: str, dst_ip: str) -> bool:
        """Check if credential is already recorded."""
        for cred in self.credentials:
            if (
                cred.auth_value == auth_value
                and cred.auth_direction == direction
                and cred.client_ip == src_ip
                and cred.server_ip == dst_ip
            ):
                return True
        return False

    def _update_devices(
        self,
        client_ip: str,
        server_ip: str,
        client_mac: str = "",
        server_mac: str = "",
    ) -> None:
        """Update device entries."""
        if is_valid_discovered_ip(server_ip):
            server_vendor = lookup_mac_vendor(server_mac) if server_mac else ""
            server_key = f"mms-server:{server_ip}"
            device, is_new = self._ensure_device(
                server_key,
                server_ip,
                mac=server_mac,
                name=f"MMS Server ({server_ip})",
                manufacturer=server_vendor if server_vendor else "",
                device_type="IED/RTU",
            )
            if is_new:
                device.mms_passive_data = {
                    "role": "server",
                    "protocol": "MMS/TCP",
                }

        if is_valid_discovered_ip(client_ip):
            client_vendor = lookup_mac_vendor(client_mac) if client_mac else ""
            client_key = f"mms-client:{client_ip}"
            device, is_new = self._ensure_device(
                client_key,
                client_ip,
                mac=client_mac,
                name=f"MMS Client ({client_ip})",
                manufacturer=client_vendor if client_vendor else "",
                device_type="SCADA/HMI",
            )
            if is_new:
                device.mms_passive_data = {
                    "role": "client",
                    "protocol": "MMS/TCP",
                }

    def _format_protocol_columns(self, ix: ProtocolInteraction) -> List[Any]:
        d = ix.details
        variable = d.get("variable", "")
        domain = d.get("domain", "")

        # For InformationReport, show rptid as variable
        if not variable and d.get("rptid"):
            variable = d["rptid"]
            if d.get("dataset"):
                domain = d["dataset"]

        # For getNameList, show object class
        if not variable and d.get("object_class"):
            variable = d["object_class"]

        # Data column: ctlVal > data
        data = ""
        if d.get("ctlVal"):
            data = f"ctlVal={d['ctlVal']}"
        elif d.get("data"):
            data = d["data"]

        return [ix.operation, variable, domain, data]

    def get_credentials_summary(self) -> List[Dict[str, Any]]:
        """Get summary of all extracted credentials."""
        return [
            {
                "protocol": "MMS/ACSE",
                "credential_type": cred.credential_type,
                "username": cred.auth_value,  # canonical key for harvest() builder
                "auth_method": cred.auth_method,
                "server_ip": cred.server_ip,
                "client_ip": cred.client_ip,
                "auth_direction": cred.auth_direction,
                "mechanism_name": cred.mechanism_name,
                "timestamp": cred.timestamp,
            }
            for cred in self.credentials
        ]

    def get_write_operations(self) -> List[Dict[str, Any]]:
        """Get interactions that are write/control operations."""
        writes: Dict[Tuple[str, str], int] = {}
        for ix in self.interactions:
            if ix.direction == "request":
                svc = ix.details.get("service_code")
                if svc is not None and svc in MMS_WRITE_SERVICES:
                    pair = (ix.src_ip, ix.dst_ip)
                    writes[pair] = writes.get(pair, 0) + 1
        return [
            {"client": client, "server": server, "write_count": count}
            for (client, server), count in writes.items()
            if count > 0
        ]
