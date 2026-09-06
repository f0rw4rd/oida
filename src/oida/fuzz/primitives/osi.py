"""
OSI Layer Primitives for MMS Protocol Stack

Implements TPKT and COTP layers as defined in:
- TPKT: RFC 1006 (ISO transport over TCP)
- COTP: ISO 8073 (Connection-Oriented Transport Protocol)
- Session: ISO 8327-1
- Presentation: ISO 8823
- ACSE: ISO 8650-1

Used for building complete MMS protocol stack.
"""

import struct
from typing import Optional
from dataclasses import dataclass


@dataclass
class TPKTHeader:
    """
    TPKT Header (RFC 1006).

    Structure:
        Byte 0:    Version (0x03)
        Byte 1:    Reserved (0x00)
        Bytes 2-3: Length (big-endian, includes header + data)
    """

    version: int = 0x03
    reserved: int = 0x00

    def encode(self, payload_length: int) -> bytes:
        """
        Encode TPKT header.

        Args:
            payload_length: Length of COTP + data

        Returns:
            4-byte TPKT header
        """
        total_length = 4 + payload_length  # TPKT header is 4 bytes
        return struct.pack(">BBH", self.version, self.reserved, total_length)


@dataclass
class COTPConnectionRequest:
    """
    COTP Connection Request (CR) PDU.

    Used for establishing connection-oriented transport.
    Includes TSAP parameters required by MMS servers (e.g. libiec61850).
    """

    dst_ref: int = 0x0000
    src_ref: int = 0x0001
    class_option: int = 0x00  # Class 0
    tpdu_size: int = 0x0D  # 8192 bytes
    src_tsap: int = 0x0001
    dst_tsap: int = 0x0001

    def encode(self) -> bytes:
        """
        Encode COTP CR PDU with TSAP parameters.

        Returns:
            COTP CR PDU bytes
        """
        pdu_data = struct.pack(">HHB", self.dst_ref, self.src_ref, self.class_option)

        # TSAP parameters
        params = bytearray()

        # C0: TPDU size
        params.extend(b"\xc0\x01")
        params.append(self.tpdu_size)

        # C2: dst-tsap (before C1 to match libiec61850 order)
        params.extend(b"\xc2\x02")
        params.extend(struct.pack(">H", self.dst_tsap))

        # C1: src-tsap
        params.extend(b"\xc1\x02")
        params.extend(struct.pack(">H", self.src_tsap))

        body = pdu_data + bytes(params)
        # LI = length of everything after LI byte (pdu_type + body)
        length = 1 + len(body)  # 1 for PDU type byte
        return struct.pack("BB", length, 0xE0) + body


@dataclass
class COTPDataTransfer:
    """
    COTP Data Transfer (DT) PDU.

    Used for transferring data over established connection.
    """

    tpdu_number: int = 0x00  # TPDU numbering (for sequencing)
    eot: bool = True  # End of TSDU (Transport Service Data Unit)

    def encode(self, data: bytes) -> bytes:
        """
        Encode COTP DT PDU.

        Args:
            data: Application data (e.g., MMS PDU)

        Returns:
            COTP DT PDU bytes
        """
        tpdu_nr_eot = (0x80 if self.eot else 0x00) | (self.tpdu_number & 0x7F)

        header = struct.pack("BBB", 0x02, 0xF0, tpdu_nr_eot)
        return header + data


class TPKTCOTPBuilder:
    """
    Builder for complete TPKT/COTP stack.

    Simplifies creation of proper OSI transport layers for MMS.
    """

    def __init__(self):
        self.tpkt = TPKTHeader()
        self.cotp_dt = COTPDataTransfer()

    def wrap_data(self, data: bytes) -> bytes:
        """
        Wrap application data in TPKT + COTP.

        Args:
            data: Application layer data (e.g., Session/Presentation/ACSE/MMS)

        Returns:
            Complete TPKT + COTP + data packet
        """
        # Build COTP DT PDU
        cotp_pdu = self.cotp_dt.encode(data)

        # Build TPKT header
        tpkt_header = self.tpkt.encode(len(cotp_pdu))

        return tpkt_header + cotp_pdu

    def build_connection_request(self) -> bytes:
        """
        Build TPKT + COTP CR (Connection Request).

        Returns:
            Complete connection request packet
        """
        cotp_cr = COTPConnectionRequest()
        cotp_pdu = cotp_cr.encode()
        tpkt_header = self.tpkt.encode(len(cotp_pdu))
        return tpkt_header + cotp_pdu


# Session Layer Primitives (ISO 8327-1)


@dataclass
class SessionConnectSPDU:
    """
    Session Layer CONNECT SPDU (ISO 8327-1).

    Includes mandatory parameters:
    - Connect/Accept Item (PI=0x05) with Protocol Options and TSDU Max Size
    - Session User Requirements (PI=0x14)
    - Calling/Called Session Selectors (PI=0x33/0x34)
    - User data (PI=0xC1)
    """

    CONNECT_ACCEPT = 0x0E
    CONNECT = 0x0D

    def __init__(self, calling_selector: bytes = b"\x00\x01", called_selector: bytes = b"\x00\x01"):
        self.calling_selector = calling_selector
        self.called_selector = called_selector

    def encode(self, user_data: bytes, spdu_type: int = None) -> bytes:
        """
        Encode Session CONNECT SPDU with mandatory parameters.

        Args:
            user_data: Presentation layer data
            spdu_type: SPDU type (default: CONNECT)

        Returns:
            Encoded CONNECT SPDU
        """
        if spdu_type is None:
            spdu_type = self.CONNECT

        parameters = bytearray()

        # PI=0x05: Connect/Accept Item (mandatory)
        connect_accept = bytearray()
        # Sub-PI=0x13: Protocol Options (1 byte, 0x00 = no options)
        connect_accept.extend(b"\x13\x01\x00")
        # Sub-PI=0x16: TSDU Maximum Size (1 byte, 0x02 = 1024 bytes)
        connect_accept.extend(b"\x16\x01\x02")
        parameters.append(0x05)
        parameters.append(len(connect_accept))
        parameters.extend(connect_accept)

        # PI=0x14: Session User Requirements (2 bytes, 0x0002 = duplex)
        parameters.extend(b"\x14\x02\x00\x02")

        # PI=0x33: Calling Session Selector
        parameters.append(0x33)
        parameters.append(len(self.calling_selector))
        parameters.extend(self.calling_selector)

        # PI=0x34: Called Session Selector
        parameters.append(0x34)
        parameters.append(len(self.called_selector))
        parameters.extend(self.called_selector)

        # PI=0xC1: Session User Data (Presentation layer)
        if user_data:
            parameters.append(0xC1)
            if len(user_data) < 254:
                parameters.append(len(user_data))
            else:
                # Extended length encoding
                length_bytes = len(user_data).to_bytes(2, "big")
                parameters.append(0xFF)
                parameters.extend(length_bytes)
            parameters.extend(user_data)

        # Build SPDU: SI + LI + parameters
        si = spdu_type
        li = len(parameters)

        return bytes([si, li]) + bytes(parameters)


# Presentation Layer Primitives (ISO 8823)


@dataclass
class PresentationContextDefinition:
    """
    Presentation Layer Context Definition.

    Defines context-id, abstract syntax and transfer syntax for data encoding.
    """

    def __init__(
        self,
        context_id: int = 1,
        abstract_syntax: str = "2.2.1.0.1",  # ACSE OID
        transfer_syntax: str = "2.1.1",
    ):  # BER encoding
        self.context_id = context_id
        self.abstract_syntax = abstract_syntax
        self.transfer_syntax = transfer_syntax

    def encode(self) -> bytes:
        """
        Encode presentation context definition as SEQUENCE.

        Returns:
            SEQUENCE { INTEGER context-id, OID abstract-syntax,
            SEQUENCE OF { OID transfer-syntax } }
        """
        from .asn1 import (
            encode_ber_integer,
            encode_ber_object_identifier,
            encode_ber_sequence,
        )

        # Context identifier
        ctx_id = encode_ber_integer(self.context_id)

        # Abstract syntax name: raw OID (not wrapped in SEQUENCE)
        abstract_oid = encode_ber_object_identifier(self.abstract_syntax)

        # Transfer syntax name list: SEQUENCE OF OID
        transfer_oid = encode_ber_object_identifier(self.transfer_syntax)
        transfer_seq = encode_ber_sequence(transfer_oid)

        # Context-list-item: SEQUENCE { id, abstract-syntax, transfer-list }
        return encode_ber_sequence(ctx_id + abstract_oid + transfer_seq)


class PresentationCPType:
    """
    Presentation CP-type (Connect Presentation).

    Used in association establishment. Requires two contexts:
    - Context 1: ACSE (OID 2.2.1.0.1)
    - Context 3: MMS (OID 1.0.9506.2.1)
    """

    def __init__(self, context_list: list = None):
        self.context_list = context_list or [
            PresentationContextDefinition(
                context_id=1,
                abstract_syntax="2.2.1.0.1",  # ACSE
                transfer_syntax="2.1.1",
            ),
            PresentationContextDefinition(
                context_id=3,
                abstract_syntax="1.0.9506.2.1",  # MMS
                transfer_syntax="2.1.1",
            ),
        ]

    def encode(self, user_data: bytes) -> bytes:
        """
        Encode Presentation CP-type as SET.

        Args:
            user_data: ACSE layer data (AARQ APDU)

        Returns:
            Encoded CP-type PDU
        """
        from .asn1 import (
            encode_ber_context_tag,
            encode_ber_sequence,
            encode_ber_set,
            encode_ber_integer,
            encode_ber_length,
        )

        # Mode selector: [0] IMPLICIT SET { [0] IMPLICIT INTEGER 1 }
        # IMPLICIT replaces SET tag, so outer is a0, inner content is 80 01 01
        mode_value = encode_ber_context_tag(0, bytes([0x01]), False)  # 80 01 01
        mode = encode_ber_context_tag(0, mode_value, True)  # a0 03 80 01 01

        # Normal-mode-parameters: [2] IMPLICIT SEQUENCE { ... }
        # IMPLICIT replaces SEQUENCE tag, content goes directly under a2
        normal_params = bytearray()

        # [1] IMPLICIT calling-presentation-selector (OCTET STRING)
        normal_params.extend(encode_ber_context_tag(1, b"\x00\x00\x00\x01", False))

        # [2] IMPLICIT called-presentation-selector (OCTET STRING)
        normal_params.extend(encode_ber_context_tag(2, b"\x00\x00\x00\x01", False))

        # [4] IMPLICIT presentation-context-definition-list (SEQUENCE OF)
        # IMPLICIT replaces SEQUENCE OF tag, items go directly under a4
        context_defs = b""
        for ctx in self.context_list:
            context_defs += ctx.encode()
        normal_params.extend(encode_ber_context_tag(4, context_defs, True))

        # User-data: fully-encoded-data [APPLICATION 1] IMPLICIT SEQUENCE OF PDV-list
        # No context tag — fully-encoded-data tag (0x61) appears directly
        pdv_list = encode_ber_sequence(
            encode_ber_integer(1)  # presentation-context-identifier = 1 (ACSE)
            + encode_ber_context_tag(0, user_data, True)  # single-ASN1-type [0]
        )
        fully_encoded = bytes([0x61]) + encode_ber_length(len(pdv_list)) + pdv_list
        normal_params.extend(fully_encoded)

        # [2] IMPLICIT SEQUENCE — tag a2 directly wraps content (no inner SEQUENCE)
        normal_mode = encode_ber_context_tag(2, bytes(normal_params), True)

        # CP-type is a SET (tag 0x31)
        cp_contents = mode + normal_mode
        return encode_ber_set(cp_contents)


# ACSE Layer Primitives (ISO 8650-1)


class ACSEAssociateRequest:
    """
    ACSE AARQ (Associate Request) APDU.

    Used for establishing application association.
    """

    def __init__(
        self,
        application_context: str = "1.0.9506.2.3",  # MMS context
        calling_ap_title: Optional[str] = "1.1.1.999",
        called_ap_title: Optional[str] = "1.1.1.999.1",
    ):
        self.application_context = application_context
        self.calling_ap_title = calling_ap_title
        self.called_ap_title = called_ap_title

    def encode(self, user_information: bytes) -> bytes:
        """
        Encode ACSE AARQ APDU.

        Args:
            user_information: MMS Initiate Request PDU

        Returns:
            Encoded AARQ APDU (APPLICATION 0 CONSTRUCTED)
        """
        from .asn1 import (
            encode_ber_object_identifier,
            encode_ber_context_tag,
            encode_ber_integer,
            encode_ber_length,
        )

        components = bytearray()

        # Application context name (context[1]): OID
        app_ctx_oid = encode_ber_object_identifier(self.application_context)
        components.extend(encode_ber_context_tag(1, app_ctx_oid, True))

        # Called AP title (context[2]): AP-title-form2 (OID)
        if self.called_ap_title:
            called_ap = encode_ber_object_identifier(self.called_ap_title)
            components.extend(encode_ber_context_tag(2, called_ap, True))

        # Called AE qualifier (context[3]): INTEGER 12
        components.extend(encode_ber_context_tag(3, encode_ber_integer(12), True))

        # Calling AP title (context[6]): AP-title-form2 (OID)
        if self.calling_ap_title:
            calling_ap = encode_ber_object_identifier(self.calling_ap_title)
            components.extend(encode_ber_context_tag(6, calling_ap, True))

        # Calling AE qualifier (context[7]): INTEGER 12
        components.extend(encode_ber_context_tag(7, encode_ber_integer(12), True))

        # User information: [30] IMPLICIT SEQUENCE OF EXTERNAL
        # IMPLICIT means context[30] tag replaces SEQUENCE OF tag
        # EXTERNAL = [UNIVERSAL 8] CONSTRUCTED
        external_content = (
            encode_ber_integer(3)  # indirect-reference = 3 (MMS context)
            + encode_ber_context_tag(0, user_information, True)  # single-ASN1-type
        )
        # EXTERNAL tag: 0x28 = CONSTRUCTED (0x20) | UNIVERSAL 8
        external = bytes([0x28]) + encode_ber_length(len(external_content)) + external_content
        # [30] IMPLICIT replaces SEQUENCE OF — content is directly the EXTERNAL item
        components.extend(encode_ber_context_tag(30, external, True))

        # AARQ is APPLICATION 0 CONSTRUCTED = 0x60
        aarq_contents = bytes(components)
        return bytes([0x60]) + encode_ber_length(len(aarq_contents)) + aarq_contents


class MMSStackBuilder:
    """
    Complete MMS OSI Stack Builder.

    Combines TPKT, COTP, Session, Presentation, and ACSE layers.
    """

    def __init__(self):
        self.tpkt_cotp = TPKTCOTPBuilder()
        self.session = SessionConnectSPDU()
        self.presentation = PresentationCPType()
        self.acse = ACSEAssociateRequest()

    def build_initiate_request(self, mms_initiate_pdu: bytes) -> bytes:
        """
        Build complete MMS Initiate Request with full OSI stack.

        Args:
            mms_initiate_pdu: MMS Initiate Request PDU (application layer)

        Returns:
            Complete packet: TPKT + COTP + Session + Presentation + ACSE + MMS
        """
        # Layer 7: MMS Initiate Request (already provided)

        # Layer 6: ACSE - wrap MMS in AARQ
        acse_pdu = self.acse.encode(mms_initiate_pdu)

        # Layer 5: Presentation - wrap ACSE in CP-type
        presentation_pdu = self.presentation.encode(acse_pdu)

        # Layer 4: Session - wrap Presentation in CONNECT SPDU
        session_pdu = self.session.encode(presentation_pdu)

        # Layer 3/4: TPKT + COTP - wrap Session
        complete_packet = self.tpkt_cotp.wrap_data(session_pdu)

        return complete_packet

    def build_data_transfer(self, mms_pdu: bytes) -> bytes:
        """
        Build MMS data transfer (after association established).

        Wraps MMS PDU in Session Give Tokens + Data Transfer SPDUs
        and Presentation fully-encoded-data PDV-list.

        Args:
            mms_pdu: MMS PDU (Read, Write, etc.)

        Returns:
            Complete packet: TPKT + COTP + Session GT+DT + Presentation + MMS
        """
        from .asn1 import (
            encode_ber_integer,
            encode_ber_context_tag,
            encode_ber_sequence,
            encode_ber_length,
        )

        # Session Give Tokens SPDU (SI=0x01, LI=0x00)
        # Session Data Transfer SPDU (SI=0x01, LI=0x00)
        session_header = b"\x01\x00\x01\x00"

        # Presentation PDV-list: SEQUENCE { context-id=3 (MMS), [0] mms_pdu }
        pdv_list = encode_ber_sequence(
            encode_ber_integer(3)  # presentation-context-identifier = 3 (MMS)
            + encode_ber_context_tag(0, mms_pdu, True)  # single-ASN1-type [0]
        )

        # fully-encoded-data: [APPLICATION 1] IMPLICIT SEQUENCE OF PDV-list
        fully_encoded = bytes([0x61]) + encode_ber_length(len(pdv_list)) + pdv_list

        # Combine: Session headers + Presentation data
        upper_layers = session_header + fully_encoded

        # Wrap in TPKT + COTP DT
        return self.tpkt_cotp.wrap_data(upper_layers)


# Convenience function for MMS data transfer wrapping


def wrap_in_tpkt_cotp(data: bytes) -> bytes:
    """
    Wrap MMS PDU for data transfer with full OSI wrapping.

    Includes Session Give Tokens + Data Transfer SPDUs and
    Presentation PDV-list wrapping required by MMS servers.

    Args:
        data: MMS PDU data

    Returns:
        Complete TPKT + COTP + Session + Presentation + MMS packet
    """
    builder = MMSStackBuilder()
    return builder.build_data_transfer(data)
