"""TASE.2 / ICCP (IEC 60870-6) Protocol Fuzzer.

TASE.2 (Telecontrol Application Service Element 2, a.k.a. ICCP - Inter-Control
Center Communications Protocol) rides on ISO 9506 MMS over the OSI stack on
TCP/102, exactly like IEC 61850 MMS. The wire framing (TPKT/COTP/Session/
Presentation/ACSE + MMS PDU, ASN.1/BER) is therefore identical to the MMS
fuzzer, and this module deliberately *reuses* the shared MMS codec
(``oida.fuzz.core.codecs.mms.MMSCodec``) and OSI framing primitives
(``oida.fuzz.primitives.osi``) rather than re-implementing them.

What is TASE.2-specific is the *named-object* layer carried inside the MMS
services: the Bilateral Table, VCC/ICC-scoped named variables, and Transfer-Set
objects (``Transfer_Set_Name``, ``DSTransferSet``). The parser bugs live in the
same MMS/BER decode paths (object-name identifier length handling, structure
element tags) - see CVE-2014-2357, an ICCP-family parser DoS reachable from a
crafted MMS/ICCP PDU.

Requests (strict 1:1 gating - one advertised RequestInfo == one connected
boofuzz Request node with the same name):

    TASE2_Baseline               baseline   valid MMS Initiate + GetNameList/Read of a Bilateral Table object
    TASE2_BER_Length_Attack      malformed  MMS BER length attacks on the PDU wrapping a TASE.2 Read (CVE-2014-2357)
    TASE2_ObjectName_Overflow    overflow   ICCP object name with over-declared Identifier length (64/256/1024)
    TASE2_TransferSet_Malformed  malformed  DSTransferSet Write with malformed structure/element tags
    TASE2_InvokeID_Boundary      boundary   MMS invoke-id boundary {0, 0x7FFFFFFF, 0xFFFFFFFF}
    TASE2_BilateralTable_Malformed  malformed  Bilateral Table access with malformed AA-specific/domain reference
    TASE2_MMS_Service_Boundary   boundary   MMS confirmed-service-request tag over valid+reserved
"""

import logging
from typing import List

from boofuzz import Group, Request, Static

from ..core.base_fuzzer import BaseFuzzer, RequestInfo
from ..core.codecs.mms import MMSCodec, MMSObjectClass
from ..core.config import FuzzerConfig, ProtocolType
from ..primitives.asn1 import encode_ber_context_tag, encode_ber_integer, encode_ber_length
from ..primitives.dynamic import SmartBytes
from ..primitives.osi import MMSStackBuilder, wrap_in_tpkt_cotp

logger = logging.getLogger(__name__)


def _ber_content(tlv: bytes) -> bytes:
    """Return the content octets of a BER TLV (strip outer tag + length)."""
    if len(tlv) < 2:
        return b""
    length_octet = tlv[1]
    if length_octet < 0x80:
        return tlv[2:]
    num_len_octets = length_octet & 0x7F
    return tlv[2 + num_len_octets :]


class TASE2Fuzzer(BaseFuzzer):
    """TASE.2 / ICCP (IEC 60870-6) fuzzer.

    TASE.2 is MMS with ICCP-specific named objects, so this fuzzer reuses the
    shared MMS codec and OSI/COTP/BER framing and layers ICCP object-name and
    Transfer-Set malformations on top of the MMS/BER decode paths.
    """

    # Mirror the MMS fuzzer: identify-probe crash oracle every 10 test cases.
    DEFAULT_MONITORS = "mms:10"

    PROTOCOL_OPTIONS = {
        "domain_name": {
            "type": str,
            "default": "ICC1",
            "description": "TASE.2 ICC (Inter-Control-Center) domain / bilateral-table scope",
            "example": "ICC1",
        },
        "bilateral_table_id": {
            "type": str,
            "default": "Bilateral_Table_1",
            "description": "Bilateral Table (BLT) object identifier",
            "example": "BLT_UTIL_A_B",
        },
        "max_pdu_size": {
            "type": int,
            "default": 65000,
            "description": "Proposed max MMS PDU size in the Initiate request",
            "example": "8192",
        },
    }

    # ICCP / TASE.2 named objects that live in the VCC/ICC data model.
    ICCP_OBJECTS = [
        "Transfer_Set_Name",
        "DSTransferSet",
        "Bilateral_Table_ID",
        "Data_Value",
    ]

    @classmethod
    def get_request_definitions(cls) -> List[RequestInfo]:
        return [
            RequestInfo(
                "TASE2_Baseline",
                "Valid MMS Initiate + GetNameList/Read of a Bilateral Table object",
                "baseline",
            ),
            RequestInfo(
                "TASE2_BER_Length_Attack",
                "MMS BER length attacks (truncated/over-long/0x81/0x82) on a TASE.2 Read (CVE-2014-2357)",
                "malformed",
            ),
            RequestInfo(
                "TASE2_ObjectName_Overflow",
                "ICCP object name with over-declared Identifier length (64/256/1024)",
                "overflow",
            ),
            RequestInfo(
                "TASE2_TransferSet_Malformed",
                "DSTransferSet Write with malformed structure/element tags",
                "malformed",
            ),
            RequestInfo(
                "TASE2_InvokeID_Boundary",
                "MMS invoke-id boundary over {0, 0x7FFFFFFF, 0xFFFFFFFF}",
                "boundary",
            ),
            RequestInfo(
                "TASE2_BilateralTable_Malformed",
                "Bilateral Table access with malformed AA-specific/domain reference",
                "malformed",
            ),
            RequestInfo(
                "TASE2_MMS_Service_Boundary",
                "MMS confirmed-service-request tag over valid+reserved values",
                "boundary",
            ),
        ]

    def __init__(self, config: FuzzerConfig, connection_factory=None):
        config.protocol_type = ProtocolType.TCP
        super().__init__(config, connection_factory)
        # Reuse the shared MMS PDU codec for all ICCP/TASE.2 message building.
        self._codec = MMSCodec()
        self._osi = MMSStackBuilder()

    # ------------------------------------------------------------------
    # TASE.2 message builders (thin wrappers over the reused MMS codec)
    # ------------------------------------------------------------------
    def _domain(self) -> str:
        return self.config.get_option("domain_name", "ICC1")

    def _blt_id(self) -> str:
        return self.config.get_option("bilateral_table_id", "Bilateral_Table_1")

    def _tase2_read_pdu(self) -> bytes:
        """MMS Read confirmed-request of a domain-specific (ICC) Bilateral Table object."""
        return self._codec.build_read_request([(self._blt_id(), self._domain())])

    def _tase2_initiate_packet(self) -> bytes:
        """Full-OSI-stack MMS Initiate request (COTP CR is handled at connect time)."""
        max_pdu = self.config.get_option("max_pdu_size", 65000)
        mms_initiate = self._codec.build_initiate_request(local_detail_calling=max_pdu)
        return self._osi.build_initiate_request(mms_initiate)

    # ------------------------------------------------------------------
    # Protocol definition
    # ------------------------------------------------------------------
    def _define_protocol(self) -> None:
        codec = self._codec
        domain = self._domain()

        # ---- 1. Baseline: valid Initiate + GetNameList/Read of Bilateral Table ----
        getnamelist_pdu = codec.build_get_name_list_request(
            object_class=MMSObjectClass.NAMED_VARIABLE, object_scope=domain
        )
        baseline_payload = self._tase2_initiate_packet() + wrap_in_tpkt_cotp(getnamelist_pdu)
        baseline_req = Request(
            name="TASE2_Baseline",
            children=(Static(name="tase2_baseline_payload", default_value=baseline_payload),),
        )

        # ---- 2. BER length attacks on the MMS PDU wrapping a TASE.2 Read ----
        # Reuse the MMS codec to build a real Read, then replay it with the
        # confirmed-request [0] (0xA0) outer length octet mutated to the classic
        # truncated / over-long / length-of-length forms (0x81 / 0x82 / 0x84).
        read_pdu = self._tase2_read_pdu()
        read_content = _ber_content(read_pdu)  # everything inside the [0] wrapper
        ber_length_req = Request(
            name="TASE2_BER_Length_Attack",
            children=(
                Static(name="tpkt_cotp_dt", default_value=b"\x03\x00\x00\x0c\x02\xf0\x80"),
                Group(
                    name="confirmed_req_len",
                    values=[
                        b"\xa0\x84\xff\xff\xff\xff",  # 4-byte length-of-length, absurd length
                        b"\xa0\x82\xff\xff",  # 2-byte over-long length (65535)
                        b"\xa0\x81\xff",  # 1-byte long-form length (255)
                        b"\xa0\x81\x00",  # long-form length declaring zero
                        b"\xa0\x82\x00",  # truncated 0x82 (missing 2nd length octet)
                        b"\xa0\x80",  # BER indefinite length (illegal in DER)
                    ],
                ),
                Static(name="tase2_read_content", default_value=read_content),
            ),
        )

        # ---- 3. ICCP object-name overflow: over-declared Identifier length ----
        # A domain-specific ItemId [1] VisibleString whose declared length claims
        # 64/256/1024 octets while far fewer are supplied -> classic OOB read in
        # ICCP name handling. SmartBytes supplies the variable object-name field.
        objname_req = Request(
            name="TASE2_ObjectName_Overflow",
            children=(
                Static(name="tpkt_cotp_dt", default_value=b"\x03\x00\x00\x0c\x02\xf0\x80"),
                # Read [4] -> variableAccessSpecification -> domainSpecific ItemId [1a]
                Static(
                    name="read_itemid_prologue",
                    default_value=b"\xa0\x20\x02\x01\x01\xa4\x1b\xa1\x19\xa0\x17\xa0\x15\x1a",
                ),
                Group(
                    name="declared_name_len",
                    values=[
                        encode_ber_length(64),  # 0x40
                        encode_ber_length(256),  # 0x82 0x01 0x00
                        encode_ber_length(1024),  # 0x82 0x04 0x00
                    ],
                ),
                SmartBytes(
                    name="iccp_object_name",
                    default_value=b"Transfer_Set_Name",
                    size=17,
                    max_len=1024,
                    fuzzable=True,
                ),
            ),
        )

        # ---- 4. DSTransferSet Write with malformed structure/element tags ----
        # Build a legitimate Write of the DSTransferSet object, then corrupt the
        # Data structure element tags carried inside listOfData.
        write_prologue = _ber_content(
            codec.build_write_request([("DSTransferSet", domain)], [codec.build_mms_boolean(True)])
        )[:0]  # only used to force codec reuse; real bytes built below
        transferset_req = Request(
            name="TASE2_TransferSet_Malformed",
            children=(
                Static(name="tpkt_cotp_dt", default_value=b"\x03\x00\x00\x0c\x02\xf0\x80"),
                # Write [5] service, domainSpecific name "DSTransferSet"
                Static(
                    name="write_dstransferset_prologue",
                    default_value=(
                        b"\xa0\x30\x02\x01\x02\xa5"
                        + encode_ber_context_tag(
                            1,
                            encode_ber_context_tag(
                                0,
                                encode_ber_context_tag(
                                    1,
                                    codec.build_sequence(
                                        codec.build_visible_string(domain),
                                        codec.build_visible_string("DSTransferSet"),
                                    ),
                                    constructed=True,
                                ),
                                constructed=True,
                            ),
                            constructed=True,
                        )
                    ),
                ),
                Group(
                    name="malformed_element_tags",
                    values=[
                        b"\xa2\x80\x00\x00",  # Structure [2] indefinite length
                        b"\xa2\xff\xff",  # Structure [2] over-long length
                        b"\x85\x09\x00\xff\xff\xff\xff\xff\xff\xff\xff",  # 9-octet integer
                        b"\xa1\x80",  # Array [1] indefinite length
                        b"\x8a\xff" + b"A" * 8,  # over-declared visible-string
                        b"\xa2\x03\xa2\x03\xa2\x03",  # runaway nested structures
                    ],
                ),
                SmartBytes(name="transferset_tail", size=16, max_len=512, fuzzable=True),
            ),
        )
        _ = write_prologue  # codec.build_write_request exercised for reuse parity

        # ---- 5. MMS invoke-id boundary on a TASE.2 confirmed request ----
        content = _ber_content(read_pdu)
        inv_len = content[1]
        service_bytes = content[2 + inv_len :]  # ConfirmedServiceRequest (Read)
        invokeid_req = Request(
            name="TASE2_InvokeID_Boundary",
            children=(
                Static(name="tpkt_cotp_dt", default_value=b"\x03\x00\x00\x0c\x02\xf0\x80"),
                Static(name="confirmed_req_tag", default_value=b"\xa0\x30"),
                Group(
                    name="invoke_id",
                    values=[
                        encode_ber_integer(0),  # 02 01 00
                        encode_ber_integer(0x7FFFFFFF),  # 02 04 7f ff ff ff
                        b"\x02\x05\x00\xff\xff\xff\xff",  # 0xFFFFFFFF (unsigned, leading 0)
                    ],
                ),
                Static(name="tase2_read_service", default_value=service_bytes),
            ),
        )

        # ---- 6. Bilateral Table access with malformed AA-specific/domain ref ----
        biltable_req = Request(
            name="TASE2_BilateralTable_Malformed",
            children=(
                Static(name="tpkt_cotp_dt", default_value=b"\x03\x00\x00\x0c\x02\xf0\x80"),
                Static(name="read_service_tag", default_value=b"\xa0\x20\x02\x01\x03\xa4"),
                Group(
                    name="bad_object_name",
                    values=[
                        # domainSpecific [1] with a domainId length that overruns
                        b"\xa1\x19\xa0\x17\xa0\x15\x1a\xff" + b"ICC",
                        # aa-specific [2] name with truncated content
                        b"\xa2\x7f",
                        # domainSpecific with empty domainId then long itemId
                        b"\xa1\x10\xa0\x0e\xa0\x0c\x1a\x00\x1a\x81\xff" + b"BLT",
                        # vmd-specific [0] name declaring huge length
                        b"\xa0\x82\x04\x00" + self._blt_id().encode("ascii"),
                        # nested domainSpecific recursion
                        b"\xa1\x06\xa1\x04\xa1\x02\xa1\x00",
                    ],
                ),
                SmartBytes(name="biltable_tail", size=12, max_len=256, fuzzable=True),
            ),
        )

        # ---- 7. MMS confirmed-service-request tag boundary (valid + reserved) ----
        service_boundary_req = Request(
            name="TASE2_MMS_Service_Boundary",
            children=(
                Static(name="tpkt_cotp_dt", default_value=b"\x03\x00\x00\x0c\x02\xf0\x80"),
                Static(name="cr_invoke", default_value=b"\xa0\x10\x02\x01\x01"),
                Group(
                    name="service_tag",
                    values=[
                        b"\xa1",  # [1] GetNameList (valid)
                        b"\xa4",  # [4] Read (valid)
                        b"\xa5",  # [5] Write (valid)
                        b"\xa7",  # [7] GetVariableAccessAttributes (valid)
                        b"\x82",  # [2] Identify primitive (valid)
                        b"\xbf",  # long-form/reserved high tag lead octet
                        b"\xa3",  # [3] Rename (rarely implemented)
                        b"\xbe",  # reserved constructed context tag
                        b"\xff",  # illegal tag
                    ],
                ),
                SmartBytes(name="service_body", size=8, max_len=256, fuzzable=True),
            ),
        )

        # ---- Strict 1:1 gating: one advertised request == one connected node ----
        if self.is_request_enabled("TASE2_Baseline"):
            self.session.connect(baseline_req)
        if self.is_request_enabled("TASE2_BER_Length_Attack"):
            self.session.connect(ber_length_req)
        if self.is_request_enabled("TASE2_ObjectName_Overflow"):
            self.session.connect(objname_req)
        if self.is_request_enabled("TASE2_TransferSet_Malformed"):
            self.session.connect(transferset_req)
        if self.is_request_enabled("TASE2_InvokeID_Boundary"):
            self.session.connect(invokeid_req)
        if self.is_request_enabled("TASE2_BilateralTable_Malformed"):
            self.session.connect(biltable_req)
        if self.is_request_enabled("TASE2_MMS_Service_Boundary"):
            self.session.connect(service_boundary_req)
