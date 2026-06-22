"""
DICOM Passive Listener for medical imaging traffic analysis (ICS).

Passively captures DICOM (Digital Imaging and Communications in Medicine)
protocol traffic to extract:
- AE titles (Application Entity: calling and called)
- Association establishment and release
- DIMSE command types (C-STORE, C-FIND, C-MOVE, C-ECHO, C-GET)
- SOP Class UIDs (CT, MR, US, CR, etc.)
- Presentation contexts and transfer syntaxes
- Implementation class/version (vendor fingerprinting)
- Association rejections and aborts with reason codes
- Patient metadata exposure risks

DICOM is the standard protocol for medical imaging systems (PACS, modalities,
viewers). In healthcare OT environments, DICOM traffic often carries
unencrypted patient data (Protected Health Information / PHI) and is
accessible on TCP port 104 (or commonly 11112).

Security concerns:
- DICOM has no built-in encryption (PHI transmitted in cleartext)
- C-MOVE can redirect images to arbitrary AE destinations
- Association accepts reveal system identity and capabilities
- Patient metadata in tags is exposed in-flight

tshark fields used:
  Association (A-ASSOCIATE-RQ/AC/RJ, A-RELEASE, A-ABORT):
  - dicom.pdu.type: PDU type (FT_UINT8, 0x01=RQ, 0x02=AC, 0x03=RJ,
    0x04=Data, 0x05=Release-RQ, 0x06=Release-RP, 0x07=Abort)
  - dicom.pdu.len: PDU length (FT_UINT32)
  - dicom.assoc.version: Protocol version (FT_UINT16)
  - dicom.assoc.ae.called: Called AE Title (FT_STRING)
  - dicom.assoc.ae.calling: Calling AE Title (FT_STRING)
  - dicom.assoc.reject.result: Reject result (FT_UINT8)
  - dicom.assoc.reject.source: Reject source (FT_UINT8)
  - dicom.assoc.reject.reason: Reject reason (FT_UINT8)
  - dicom.assoc.abort.source: Abort source (FT_UINT8)
  - dicom.assoc.abort.reason: Abort reason (FT_UINT8)

  Presentation Context:
  - dicom.pctx.id: Presentation context ID (FT_UINT8)
  - dicom.pctx.result: Presentation context result (FT_UINT8)
  - dicom.pctx.abss.syntax: Abstract syntax UID (FT_STRING)
  - dicom.pctx.xfer.syntax: Transfer syntax UID (FT_STRING)

  User Information:
  - dicom.max_pdu_len: Max PDU length (FT_UINT32)
  - dicom.userinfo.uid: Implementation class UID (FT_STRING)
  - dicom.userinfo.version: Implementation version (FT_STRING)

  Data (P-DATA-TF):
  - dicom.pdv.ctx: PDV context ID (FT_UINT8)
  - dicom.pdv.flags: PDV flags (FT_UINT8)
  - dicom.tag: DICOM tag (FT_UINT32)
  - dicom.tag.vr: Value Representation (FT_STRING)
  - dicom.tag.value.str: Tag string value (FT_STRING)
  - dicom.tag.value.16u: Tag uint16 value (FT_UINT16)

References:
- DICOM Standard PS3.7: Message Exchange
- DICOM Standard PS3.8: Network Communication Support
- Wireshark dissector: packet-dcm.c
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Tuple

from .pyshark_base import ProtocolInteraction, PySharkListenerBase
from ..protocols.discovery.core import is_valid_discovered_ip, lookup_mac_vendor

# DICOM PDU types
DICOM_PDU_TYPES = {
    0x01: "A-ASSOCIATE-RQ",
    0x02: "A-ASSOCIATE-AC",
    0x03: "A-ASSOCIATE-RJ",
    0x04: "P-DATA-TF",
    0x05: "A-RELEASE-RQ",
    0x06: "A-RELEASE-RP",
    0x07: "A-ABORT",
}

# DICOM DIMSE command fields (from command group 0000)
# Identified by command field tag (0000,0100) values
DICOM_COMMANDS = {
    0x0001: "C-STORE-RQ",
    0x8001: "C-STORE-RSP",
    0x0010: "C-GET-RQ",
    0x8010: "C-GET-RSP",
    0x0020: "C-FIND-RQ",
    0x8020: "C-FIND-RSP",
    0x0021: "C-MOVE-RQ",
    0x8021: "C-MOVE-RSP",
    0x0030: "C-ECHO-RQ",
    0x8030: "C-ECHO-RSP",
    0x0100: "N-EVENT-REPORT-RQ",
    0x8100: "N-EVENT-REPORT-RSP",
    0x0110: "N-GET-RQ",
    0x8110: "N-GET-RSP",
    0x0120: "N-SET-RQ",
    0x8120: "N-SET-RSP",
    0x0130: "N-ACTION-RQ",
    0x8130: "N-ACTION-RSP",
    0x0140: "N-CREATE-RQ",
    0x8140: "N-CREATE-RSP",
    0x0150: "N-DELETE-RQ",
    0x8150: "N-DELETE-RSP",
    0x0FFF: "C-CANCEL-RQ",
}

# Common SOP Class UIDs (Abstract Syntax) -> short names
DICOM_SOP_CLASSES = {
    "1.2.840.10008.1.1": "Verification",  # C-ECHO
    "1.2.840.10008.5.1.4.1.1.2": "CT Image",
    "1.2.840.10008.5.1.4.1.1.2.1": "Enhanced CT",
    "1.2.840.10008.5.1.4.1.1.4": "MR Image",
    "1.2.840.10008.5.1.4.1.1.4.1": "Enhanced MR",
    "1.2.840.10008.5.1.4.1.1.1": "CR Image",
    "1.2.840.10008.5.1.4.1.1.1.1": "Digital X-Ray",
    "1.2.840.10008.5.1.4.1.1.6.1": "Ultrasound Image",
    "1.2.840.10008.5.1.4.1.1.7": "SC Image",  # Secondary Capture
    "1.2.840.10008.5.1.4.1.1.12.1": "X-Ray Angiographic",
    "1.2.840.10008.5.1.4.1.1.12.2": "X-Ray RF",
    "1.2.840.10008.5.1.4.1.1.20": "NM Image",
    "1.2.840.10008.5.1.4.1.1.128": "PET Image",
    "1.2.840.10008.5.1.4.1.1.481.1": "RT Image",
    "1.2.840.10008.5.1.4.1.1.481.2": "RT Dose",
    "1.2.840.10008.5.1.4.1.1.481.3": "RT Structure Set",
    "1.2.840.10008.5.1.4.1.1.481.5": "RT Plan",
    "1.2.840.10008.5.1.4.1.1.88.11": "Basic Text SR",
    "1.2.840.10008.5.1.4.1.1.88.22": "Enhanced SR",
    "1.2.840.10008.5.1.4.1.1.104.1": "Encapsulated PDF",
    "1.2.840.10008.5.1.4.1.2.1.1": "Patient Root QR Find",
    "1.2.840.10008.5.1.4.1.2.1.2": "Patient Root QR Move",
    "1.2.840.10008.5.1.4.1.2.1.3": "Patient Root QR Get",
    "1.2.840.10008.5.1.4.1.2.2.1": "Study Root QR Find",
    "1.2.840.10008.5.1.4.1.2.2.2": "Study Root QR Move",
    "1.2.840.10008.5.1.4.1.2.2.3": "Study Root QR Get",
    "1.2.840.10008.5.1.4.32.1": "Modality Worklist Find",
    "1.2.840.10008.5.1.4.33": "Modality Performed Procedure Step",
    "1.2.840.10008.3.1.2.3.3": "Modality Performed Procedure Step SOP",
    "1.2.840.10008.1.20.1": "Storage Commitment Push Model",
}

# DICOM reject reasons (source: DICOM PS3.8 Table 9-21)
DICOM_REJECT_RESULTS = {
    1: "Rejected (Permanent)",
    2: "Rejected (Transient)",
}
DICOM_REJECT_SOURCES = {
    1: "DICOM UL Service User",
    2: "DICOM UL Service Provider (ACSE)",
    3: "DICOM UL Service Provider (Presentation)",
}
DICOM_REJECT_REASONS_USER = {
    1: "No reason given",
    2: "Application context name not supported",
    3: "Calling AE title not recognized",
    7: "Called AE title not recognized",
}
DICOM_REJECT_REASONS_ACSE = {
    1: "No reason given",
    2: "Protocol version not supported",
}

# DICOM abort reasons
DICOM_ABORT_SOURCES = {
    0: "DICOM UL Service User",
    2: "DICOM UL Service Provider",
}
DICOM_ABORT_REASONS = {
    0: "Reason not specified",
    1: "Unrecognized PDU",
    2: "Unexpected PDU",
    4: "Unrecognized PDU parameter",
    5: "Unexpected PDU parameter",
    6: "Invalid PDU parameter value",
}

# Sensitive DICOM tags that indicate PHI exposure
PHI_TAGS = {
    0x00100010: "PatientName",
    0x00100020: "PatientID",
    0x00100030: "PatientBirthDate",
    0x00100040: "PatientSex",
    0x00080050: "AccessionNumber",
    0x00080080: "InstitutionName",
    0x00080090: "ReferringPhysicianName",
    0x00081030: "StudyDescription",
    0x00081070: "OperatorsName",
}

# Write/modify DIMSE commands (security-relevant)
DICOM_WRITE_COMMANDS = {0x0001, 0x0021, 0x0120, 0x0130, 0x0140, 0x0150}


@dataclass
class DICOMAssociation:
    """Track a DICOM association."""

    calling_ae: str
    called_ae: str
    client_ip: str
    server_ip: str
    sop_classes: Set[str] = field(default_factory=set)
    commands_seen: Set[str] = field(default_factory=set)
    impl_version: str = ""
    accepted: bool = False
    phi_exposed: bool = False
    first_seen: str = ""
    last_seen: str = ""


class DICOMPassiveListener(PySharkListenerBase):
    """Passive DICOM traffic listener for medical imaging analysis.

    Captures DICOM traffic to extract:
    - Association establishments (AE titles, SOP classes)
    - DIMSE commands (C-STORE, C-FIND, C-MOVE, C-ECHO)
    - Implementation fingerprinting (class UID, version)
    - Association rejections and aborts with reasons
    - PHI exposure indicators
    """

    PROTOCOL_NAME = "dicom"
    DISPLAY_FILTER = "dicom"
    REQUIRED_LAYERS = ("dicom",)
    PROTOCOL_COLUMNS = ("pdu_type", "calling_ae", "called_ae", "sop_class", "detail")

    def __init__(
        self,
        interface: str,
        timeout: int = 60,
        nxc_logger: Optional[Any] = None,
    ):
        super().__init__(interface, timeout, nxc_logger)
        self.associations: Dict[Tuple[str, str], DICOMAssociation] = {}

    def process_packet(self, packet) -> None:
        """Process DICOM packet."""
        if not hasattr(packet, "dicom"):
            return

        dicom = packet.dicom
        src_ip, dst_ip = self.get_ip_info(packet)
        if not src_ip or not dst_ip:
            return

        flow_id = self.get_flow_id(packet)
        src_port, dst_port = self.get_port_info(packet)
        stream_id = self.get_stream_id(packet)
        src_mac, dst_mac = self.get_mac_info(packet)
        now = datetime.now().isoformat()

        # Get PDU type
        pdu_type_raw = self.get_field(dicom, "pdu_type", None)
        if pdu_type_raw is None:
            pdu_type_raw = self.get_field(dicom, "pdu.type", None)
        pdu_type = self._parse_int(pdu_type_raw, None, base=16)

        if pdu_type is None:
            return

        pdu_name = DICOM_PDU_TYPES.get(pdu_type, f"PDU 0x{pdu_type:02x}")

        if pdu_type == 0x01:
            self._process_associate_rq(
                dicom,
                pdu_name,
                src_ip,
                dst_ip,
                src_mac,
                dst_mac,
                flow_id,
                src_port,
                dst_port,
                stream_id,
                now,
            )
        elif pdu_type == 0x02:
            self._process_associate_ac(
                dicom,
                pdu_name,
                src_ip,
                dst_ip,
                src_mac,
                dst_mac,
                flow_id,
                src_port,
                dst_port,
                stream_id,
                now,
            )
        elif pdu_type == 0x03:
            self._process_associate_rj(
                dicom,
                pdu_name,
                src_ip,
                dst_ip,
                flow_id,
                src_port,
                dst_port,
                stream_id,
                now,
            )
        elif pdu_type == 0x04:
            self._process_data(
                dicom,
                pdu_name,
                src_ip,
                dst_ip,
                flow_id,
                src_port,
                dst_port,
                stream_id,
                now,
            )
        elif pdu_type in (0x05, 0x06):
            self._process_release(
                pdu_name,
                pdu_type,
                src_ip,
                dst_ip,
                flow_id,
                src_port,
                dst_port,
                stream_id,
                now,
            )
        elif pdu_type == 0x07:
            self._process_abort(
                dicom,
                pdu_name,
                src_ip,
                dst_ip,
                flow_id,
                src_port,
                dst_port,
                stream_id,
                now,
            )

    def _process_associate_rq(
        self,
        dicom,
        pdu_name: str,
        src_ip: str,
        dst_ip: str,
        src_mac: str,
        dst_mac: str,
        flow_id: str,
        src_port: int,
        dst_port: int,
        stream_id: str,
        now: str,
    ) -> None:
        """Process A-ASSOCIATE-RQ (association request)."""
        calling_ae = str(self.get_field(dicom, "assoc_ae_calling", "") or "").strip()
        if not calling_ae:
            calling_ae = str(self.get_field(dicom, "assoc.ae.calling", "") or "").strip()
        called_ae = str(self.get_field(dicom, "assoc_ae_called", "") or "").strip()
        if not called_ae:
            called_ae = str(self.get_field(dicom, "assoc.ae.called", "") or "").strip()
        version = self._parse_int(self.get_field(dicom, "assoc_version", None), None)
        if version is None:
            version = self._parse_int(self.get_field(dicom, "assoc.version", None), None)

        # Presentation contexts
        abss_syntax = str(self.get_field(dicom, "pctx_abss_syntax", "") or "").strip()
        if not abss_syntax:
            abss_syntax = str(self.get_field(dicom, "pctx.abss.syntax", "") or "").strip()
        xfer_syntax = str(self.get_field(dicom, "pctx_xfer_syntax", "") or "").strip()
        if not xfer_syntax:
            xfer_syntax = str(self.get_field(dicom, "pctx.xfer.syntax", "") or "").strip()

        # User info
        impl_uid = str(self.get_field(dicom, "userinfo_uid", "") or "").strip()
        if not impl_uid:
            impl_uid = str(self.get_field(dicom, "userinfo.uid", "") or "").strip()
        impl_version = str(self.get_field(dicom, "userinfo_version", "") or "").strip()
        if not impl_version:
            impl_version = str(self.get_field(dicom, "userinfo.version", "") or "").strip()
        max_pdu = self._parse_int(self.get_field(dicom, "max_pdu_len", None), None)

        sop_name = DICOM_SOP_CLASSES.get(abss_syntax, abss_syntax) if abss_syntax else ""

        details: Dict[str, Any] = {
            "pdu_type": pdu_name,
            "calling_ae": calling_ae,
            "called_ae": called_ae,
        }
        if version is not None:
            details["version"] = version
        if abss_syntax:
            details["abstract_syntax"] = abss_syntax
            details["sop_class_name"] = sop_name
        if xfer_syntax:
            details["transfer_syntax"] = xfer_syntax
        if impl_uid:
            details["impl_class_uid"] = impl_uid
        if impl_version:
            details["impl_version"] = impl_version
        if max_pdu is not None:
            details["max_pdu_length"] = max_pdu

        summary = f"A-ASSOCIATE-RQ {calling_ae} -> {called_ae}"
        if sop_name:
            summary = f"{summary} [{sop_name}]"

        self._record_interaction(
            now,
            src_ip,
            dst_ip,
            "request",
            pdu_name,
            details,
            summary,
            flow_id=flow_id,
            src_port=src_port,
            dst_port=dst_port,
            stream_id=stream_id,
        )

        # Track association
        assoc_key = (src_ip, dst_ip)
        assoc = DICOMAssociation(
            calling_ae=calling_ae,
            called_ae=called_ae,
            client_ip=src_ip,
            server_ip=dst_ip,
            impl_version=impl_version,
            first_seen=now,
            last_seen=now,
        )
        if abss_syntax:
            assoc.sop_classes.add(sop_name or abss_syntax)
        self.associations[assoc_key] = assoc

        # Update devices
        self._update_devices(src_ip, dst_ip, src_mac, dst_mac, calling_ae, called_ae)

    def _process_associate_ac(
        self,
        dicom,
        pdu_name: str,
        src_ip: str,
        dst_ip: str,
        src_mac: str,
        dst_mac: str,
        flow_id: str,
        src_port: int,
        dst_port: int,
        stream_id: str,
        now: str,
    ) -> None:
        """Process A-ASSOCIATE-AC (association accept)."""
        calling_ae = str(self.get_field(dicom, "assoc_ae_calling", "") or "").strip()
        if not calling_ae:
            calling_ae = str(self.get_field(dicom, "assoc.ae.calling", "") or "").strip()
        called_ae = str(self.get_field(dicom, "assoc_ae_called", "") or "").strip()
        if not called_ae:
            called_ae = str(self.get_field(dicom, "assoc.ae.called", "") or "").strip()

        impl_uid = str(self.get_field(dicom, "userinfo_uid", "") or "").strip()
        if not impl_uid:
            impl_uid = str(self.get_field(dicom, "userinfo.uid", "") or "").strip()
        impl_version = str(self.get_field(dicom, "userinfo_version", "") or "").strip()
        if not impl_version:
            impl_version = str(self.get_field(dicom, "userinfo.version", "") or "").strip()

        abss_syntax = str(self.get_field(dicom, "pctx_abss_syntax", "") or "").strip()
        if not abss_syntax:
            abss_syntax = str(self.get_field(dicom, "pctx.abss.syntax", "") or "").strip()
        sop_name = DICOM_SOP_CLASSES.get(abss_syntax, abss_syntax) if abss_syntax else ""

        details: Dict[str, Any] = {
            "pdu_type": pdu_name,
            "calling_ae": calling_ae,
            "called_ae": called_ae,
        }
        if impl_uid:
            details["impl_class_uid"] = impl_uid
        if impl_version:
            details["impl_version"] = impl_version
        if sop_name:
            details["sop_class_name"] = sop_name

        summary = f"A-ASSOCIATE-AC {called_ae} -> {calling_ae}"
        if impl_version:
            summary = f"{summary} [{impl_version}]"

        self._record_interaction(
            now,
            src_ip,
            dst_ip,
            "response",
            pdu_name,
            details,
            summary,
            flow_id=flow_id,
            src_port=src_port,
            dst_port=dst_port,
            stream_id=stream_id,
        )

        # Mark association as accepted
        # Response comes from server (src) to client (dst)
        assoc_key = (dst_ip, src_ip)
        if assoc_key in self.associations:
            self.associations[assoc_key].accepted = True
            self.associations[assoc_key].last_seen = now
            if impl_version:
                self.associations[assoc_key].impl_version = impl_version

        self._update_devices(dst_ip, src_ip, "", "", calling_ae, called_ae)

    def _process_associate_rj(
        self,
        dicom,
        pdu_name: str,
        src_ip: str,
        dst_ip: str,
        flow_id: str,
        src_port: int,
        dst_port: int,
        stream_id: str,
        now: str,
    ) -> None:
        """Process A-ASSOCIATE-RJ (association reject)."""
        result_raw = self.get_field(dicom, "assoc_reject_result", None)
        if result_raw is None:
            result_raw = self.get_field(dicom, "assoc.reject.result", None)
        result = self._parse_int(result_raw, None)

        source_raw = self.get_field(dicom, "assoc_reject_source", None)
        if source_raw is None:
            source_raw = self.get_field(dicom, "assoc.reject.source", None)
        source = self._parse_int(source_raw, None)

        reason_raw = self.get_field(dicom, "assoc_reject_reason", None)
        if reason_raw is None:
            reason_raw = self.get_field(dicom, "assoc.reject.reason", None)
        reason = self._parse_int(reason_raw, None)

        details: Dict[str, Any] = {"pdu_type": pdu_name}
        summary_parts = ["A-ASSOCIATE-RJ"]

        if result is not None:
            result_name = DICOM_REJECT_RESULTS.get(result, f"result={result}")
            details["reject_result"] = result
            details["reject_result_name"] = result_name
            summary_parts.append(result_name)
        if source is not None:
            source_name = DICOM_REJECT_SOURCES.get(source, f"source={source}")
            details["reject_source"] = source
            details["reject_source_name"] = source_name
        if reason is not None:
            # Reason interpretation depends on source
            if source == 1:
                reason_name = DICOM_REJECT_REASONS_USER.get(reason, f"reason={reason}")
            elif source == 2:
                reason_name = DICOM_REJECT_REASONS_ACSE.get(reason, f"reason={reason}")
            else:
                reason_name = f"reason={reason}"
            details["reject_reason"] = reason
            details["reject_reason_name"] = reason_name
            summary_parts.append(reason_name)

        self._record_interaction(
            now,
            src_ip,
            dst_ip,
            "response",
            pdu_name,
            details,
            " ".join(summary_parts),
            flow_id=flow_id,
            src_port=src_port,
            dst_port=dst_port,
            stream_id=stream_id,
        )

    def _process_data(
        self,
        dicom,
        pdu_name: str,
        src_ip: str,
        dst_ip: str,
        flow_id: str,
        src_port: int,
        dst_port: int,
        stream_id: str,
        now: str,
    ) -> None:
        """Process P-DATA-TF (data transfer)."""
        pdv_ctx = self._parse_int(self.get_field(dicom, "pdv_ctx", None), None)
        if pdv_ctx is None:
            pdv_ctx = self._parse_int(self.get_field(dicom, "pdv.ctx", None), None)
        pdv_flags = self._parse_int(self.get_field(dicom, "pdv_flags", None), None, base=16)
        if pdv_flags is None:
            pdv_flags = self._parse_int(self.get_field(dicom, "pdv.flags", None), None, base=16)

        # Extract DICOM tags for command identification and PHI detection
        tag_raw = self.get_field(dicom, "tag", None)
        tag_value_str = str(self.get_field(dicom, "tag_value_str", "") or "").strip()
        if not tag_value_str:
            tag_value_str = str(self.get_field(dicom, "tag.value.str", "") or "").strip()
        tag_value_16u = self._parse_int(self.get_field(dicom, "tag_value_16u", None), None)
        if tag_value_16u is None:
            tag_value_16u = self._parse_int(self.get_field(dicom, "tag.value.16u", None), None)

        details: Dict[str, Any] = {"pdu_type": pdu_name}
        if pdv_ctx is not None:
            details["pdv_context"] = pdv_ctx
        if pdv_flags is not None:
            details["pdv_flags"] = pdv_flags

        # Try to identify DIMSE command from tag (0000,0100)
        command_name = ""
        if tag_value_16u is not None:
            command_name = DICOM_COMMANDS.get(tag_value_16u, "")
            if command_name:
                details["dimse_command"] = command_name
                details["command_field"] = tag_value_16u

        # Check for PHI exposure in tag values
        if tag_raw is not None:
            # base 10 default: EK mode normalizes the FT_UINT32 dicom.tag to a
            # decimal string (e.g. 0x00100010 -> "1048592"); XML-mode "0x"-prefixed
            # hex is still auto-detected by _parse_int.
            tag_int = self._parse_int(tag_raw, None)
            if tag_int is not None and tag_int in PHI_TAGS:
                details["phi_tag"] = PHI_TAGS[tag_int]
                details["phi_exposed"] = True
                if tag_value_str:
                    details["phi_value_present"] = True
                # Mark on association
                for assoc in self.associations.values():
                    if (assoc.client_ip == src_ip and assoc.server_ip == dst_ip) or (
                        assoc.client_ip == dst_ip and assoc.server_ip == src_ip
                    ):
                        assoc.phi_exposed = True

        # Determine direction from PDV flags
        # Bit 0: command(0) or data(1), Bit 1: last fragment
        is_command = pdv_flags is not None and (pdv_flags & 0x01) == 0
        direction = "request" if is_command else "response"

        # Build operation name
        operation = command_name or pdu_name
        summary = command_name or "P-DATA-TF"
        if details.get("phi_tag"):
            summary = f"{summary} [PHI: {details['phi_tag']}]"

        # Update association with command
        for assoc in self.associations.values():
            if (assoc.client_ip == src_ip and assoc.server_ip == dst_ip) or (
                assoc.client_ip == dst_ip and assoc.server_ip == src_ip
            ):
                assoc.last_seen = now
                if command_name:
                    assoc.commands_seen.add(command_name)

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

    def _process_release(
        self,
        pdu_name: str,
        pdu_type: int,
        src_ip: str,
        dst_ip: str,
        flow_id: str,
        src_port: int,
        dst_port: int,
        stream_id: str,
        now: str,
    ) -> None:
        """Process A-RELEASE-RQ/RP."""
        direction = "request" if pdu_type == 0x05 else "response"
        details: Dict[str, Any] = {"pdu_type": pdu_name}
        self._record_interaction(
            now,
            src_ip,
            dst_ip,
            direction,
            pdu_name,
            details,
            pdu_name,
            flow_id=flow_id,
            src_port=src_port,
            dst_port=dst_port,
            stream_id=stream_id,
        )

    def _process_abort(
        self,
        dicom,
        pdu_name: str,
        src_ip: str,
        dst_ip: str,
        flow_id: str,
        src_port: int,
        dst_port: int,
        stream_id: str,
        now: str,
    ) -> None:
        """Process A-ABORT."""
        source_raw = self.get_field(dicom, "assoc_abort_source", None)
        if source_raw is None:
            source_raw = self.get_field(dicom, "assoc.abort.source", None)
        source = self._parse_int(source_raw, None)

        reason_raw = self.get_field(dicom, "assoc_abort_reason", None)
        if reason_raw is None:
            reason_raw = self.get_field(dicom, "assoc.abort.reason", None)
        reason = self._parse_int(reason_raw, None)

        details: Dict[str, Any] = {"pdu_type": pdu_name}
        summary_parts = ["A-ABORT"]

        if source is not None:
            source_name = DICOM_ABORT_SOURCES.get(source, f"source={source}")
            details["abort_source"] = source
            details["abort_source_name"] = source_name
            summary_parts.append(source_name)
        if reason is not None:
            reason_name = DICOM_ABORT_REASONS.get(reason, f"reason={reason}")
            details["abort_reason"] = reason
            details["abort_reason_name"] = reason_name
            summary_parts.append(reason_name)

        self._record_interaction(
            now,
            src_ip,
            dst_ip,
            "response",
            pdu_name,
            details,
            " ".join(summary_parts),
            flow_id=flow_id,
            src_port=src_port,
            dst_port=dst_port,
            stream_id=stream_id,
        )

    def _update_devices(
        self,
        client_ip: str,
        server_ip: str,
        client_mac: str = "",
        server_mac: str = "",
        calling_ae: str = "",
        called_ae: str = "",
    ) -> None:
        """Update device entries."""
        if is_valid_discovered_ip(server_ip):
            server_vendor = lookup_mac_vendor(server_mac) if server_mac else ""
            server_key = f"dicom-server:{server_ip}"
            name = f"DICOM Server ({called_ae})" if called_ae else f"DICOM Server ({server_ip})"
            device, is_new = self._ensure_device(
                server_key,
                server_ip,
                mac=server_mac,
                name=name,
                manufacturer=server_vendor if server_vendor else "",
                device_type="PACS/DICOM Server",
            )
            if is_new:
                device.dicom_passive_data = {
                    "role": "server",
                    "protocol": "DICOM",
                    "ae_title": called_ae,
                }

        if is_valid_discovered_ip(client_ip):
            client_vendor = lookup_mac_vendor(client_mac) if client_mac else ""
            client_key = f"dicom-client:{client_ip}"
            name = f"DICOM Client ({calling_ae})" if calling_ae else f"DICOM Client ({client_ip})"
            device, is_new = self._ensure_device(
                client_key,
                client_ip,
                mac=client_mac,
                name=name,
                manufacturer=client_vendor if client_vendor else "",
                device_type="DICOM Modality/Viewer",
            )
            if is_new:
                device.dicom_passive_data = {
                    "role": "client",
                    "protocol": "DICOM",
                    "ae_title": calling_ae,
                }

    def _format_protocol_columns(self, ix: ProtocolInteraction) -> List[Any]:
        d = ix.details
        pdu_type = d.get("pdu_type", "")
        calling_ae = d.get("calling_ae", "")
        called_ae = d.get("called_ae", "")
        sop_class = d.get("sop_class_name", "")
        # Build detail
        detail_parts = []
        if d.get("dimse_command"):
            detail_parts.append(d["dimse_command"])
        if d.get("impl_version"):
            detail_parts.append(f"impl={d['impl_version']}")
        if d.get("phi_tag"):
            detail_parts.append(f"[PHI:{d['phi_tag']}]")
        if d.get("reject_result_name"):
            detail_parts.append(d["reject_result_name"])
        if d.get("abort_reason_name"):
            detail_parts.append(d["abort_reason_name"])
        detail = " ".join(detail_parts)
        return [pdu_type, calling_ae, called_ae, sop_class, detail]

    def harvest(self) -> Dict[str, Any]:
        """Return harvest with PHI exposure and unencrypted traffic alerts."""
        result = super().harvest()
        alerts = result.get("alerts", [])

        # PHI exposure alerts
        for assoc in self.associations.values():
            if assoc.phi_exposed:
                alerts.append(
                    {
                        "level": "fail",
                        "category": "phi_exposure",
                        "message": (
                            f"DICOM PHI EXPOSURE: {assoc.calling_ae} -> {assoc.called_ae} "
                            f"({assoc.client_ip} -> {assoc.server_ip}) "
                            "patient data transmitted in cleartext"
                        ),
                    }
                )

        # Unencrypted DICOM on standard port
        if self.associations:
            alerts.append(
                {
                    "level": "warning",
                    "category": "cleartext",
                    "message": (
                        f"DICOM: {len(self.associations)} association(s) observed "
                        "without TLS encryption"
                    ),
                }
            )

        if alerts:
            result["alerts"] = alerts
        return result

    def get_write_operations(self) -> List[Dict[str, Any]]:
        """Get interactions with write/modify commands."""
        writes: Dict[Tuple[str, str], int] = {}
        for ix in self.interactions:
            if ix.direction == "request":
                cmd_field = ix.details.get("command_field")
                if cmd_field is not None and cmd_field in DICOM_WRITE_COMMANDS:
                    pair = (ix.src_ip, ix.dst_ip)
                    writes[pair] = writes.get(pair, 0) + 1
        return [
            {"client": src, "server": dst, "write_count": count}
            for (src, dst), count in writes.items()
            if count > 0
        ]

    def get_sessions_summary(self) -> List[Dict[str, Any]]:
        """Get summary of all observed DICOM associations."""
        return [
            {
                "calling_ae": a.calling_ae,
                "called_ae": a.called_ae,
                "client": a.client_ip,
                "server": a.server_ip,
                "accepted": a.accepted,
                "sop_classes": sorted(a.sop_classes),
                "commands": sorted(a.commands_seen),
                "impl_version": a.impl_version,
                "phi_exposed": a.phi_exposed,
                "first_seen": a.first_seen,
                "last_seen": a.last_seen,
            }
            for a in self.associations.values()
        ]
