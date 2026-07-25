"""
MMS (Manufacturing Message Specification) protocol codec.

Provides ASN.1/BER encoding for MMS PDUs used by TASE.2/ICCP and IEC 61850.

References:
- ISO 9506-1/2 (MMS)
- IEC 60870-6 (TASE.2)
- IEC 61850-8-1 (MMS for power utility automation)

MMS PDU Types:
- Confirmed-RequestPDU [0]
- Confirmed-ResponsePDU [1]
- Confirmed-ErrorPDU [2]
- Unconfirmed-PDU [3]
- Initiate-RequestPDU [8]
- Initiate-ResponsePDU [9]
- Initiate-ErrorPDU [10]
- Conclude-RequestPDU [11]
- Conclude-ResponsePDU [12]
- Conclude-ErrorPDU [13]
"""

from typing import List, Optional, Tuple
from .asn1 import ASN1Builder


class MMSServiceType:
    """MMS service type constants for ConfirmedServiceRequest/Response."""

    # VMD Support
    STATUS = 0
    GET_NAME_LIST = 1
    IDENTIFY = 2
    RENAME = 3

    # Domain Management
    GET_DOMAIN_ATTRIBUTES = 6

    # Variable Access
    READ = 4
    WRITE = 5
    GET_VARIABLE_ACCESS_ATTRIBUTES = 7
    DEFINE_NAMED_VARIABLE = 8
    DEFINE_SCATTERED_ACCESS = 9
    GET_SCATTERED_ACCESS_ATTRIBUTES = 10
    DELETE_VARIABLE_ACCESS = 11
    DEFINE_NAMED_VARIABLE_LIST = 12
    GET_NAMED_VARIABLE_LIST_ATTRIBUTES = 13
    DELETE_NAMED_VARIABLE_LIST = 14
    DEFINE_NAMED_TYPE = 15
    GET_NAMED_TYPE_ATTRIBUTES = 16
    DELETE_NAMED_TYPE = 17

    # Semaphore Management
    OBTAIN_FILE = 46
    READ_JOURNAL = 65
    WRITE_JOURNAL = 66
    INITIALIZE_JOURNAL = 67
    REPORT_JOURNAL_STATUS = 68
    CREATE_JOURNAL = 69
    DELETE_JOURNAL = 70

    # File Management
    FILE_OPEN = 72
    FILE_READ = 73
    FILE_CLOSE = 74
    FILE_RENAME = 75
    FILE_DELETE = 76
    FILE_DIRECTORY = 77

    # Information Report (Unconfirmed)
    INFORMATION_REPORT = 0


class MMSObjectClass:
    """MMS object class constants for GetNameList."""

    NAMED_VARIABLE = 0
    SCATTERED_ACCESS = 1
    NAMED_VARIABLE_LIST = 2
    NAMED_TYPE = 3
    SEMAPHORE = 4
    EVENT_CONDITION = 5
    EVENT_ACTION = 6
    EVENT_ENROLLMENT = 7
    JOURNAL = 8
    DOMAIN = 9
    PROGRAM_INVOCATION = 10
    OPERATOR_STATION = 11


class MMSCodec(ASN1Builder):
    """
    MMS protocol PDU encoder/decoder.

    Extends ASN1Builder with MMS-specific PDU construction methods.
    Used as the foundation for TASE.2 and IEC 61850 fuzzers.
    """

    def __init__(self):
        """Initialize MMS codec."""
        super().__init__()
        self._invoke_id_counter = 0

    def next_invoke_id(self) -> int:
        """Get next invoke ID and increment counter."""
        invoke_id = self._invoke_id_counter
        self._invoke_id_counter = (self._invoke_id_counter + 1) % 0x100000000
        return invoke_id

    # =========================================================================
    # PDU Frame Builders
    # =========================================================================

    def build_confirmed_request(self, invoke_id: int, service: bytes) -> bytes:
        """
        Build a Confirmed-RequestPDU.

        Structure:
            Confirmed-RequestPDU ::= [0] IMPLICIT SEQUENCE {
                invokeID    Unsigned32,
                service     ConfirmedServiceRequest
            }

        Args:
            invoke_id: Request invoke ID
            service: Encoded ConfirmedServiceRequest

        Returns:
            BER-encoded Confirmed-RequestPDU
        """
        content = self.build_sequence(self.build_unsigned32(invoke_id), service)
        # Remove SEQUENCE tag, use context-specific [0] IMPLICIT
        return self.build_context_specific(0, content[2:], constructed=True)

    def build_initiate_request(
        self,
        local_detail_calling: int = 65000,
        proposed_max_serv_outstanding_calling: int = 5,
        proposed_max_serv_outstanding_called: int = 5,
        proposed_data_structure_nesting_level: int = 4,
        init_request_detail: Optional[bytes] = None,
    ) -> bytes:
        """
        Build an Initiate-RequestPDU.

        Structure:
            Initiate-RequestPDU ::= [8] IMPLICIT SEQUENCE {
                localDetailCalling                    [0] IMPLICIT Integer32 OPTIONAL,
                proposedMaxServOutstandingCalling     [1] IMPLICIT Integer16,
                proposedMaxServOutstandingCalled      [2] IMPLICIT Integer16,
                proposedDataStructureNestingLevel     [3] IMPLICIT Integer8 OPTIONAL,
                mmsInitRequestDetail                  [4] IMPLICIT InitRequestDetail OPTIONAL
            }

        Args:
            local_detail_calling: Local detail (max PDU size)
            proposed_max_serv_outstanding_calling: Max outstanding requests
            proposed_max_serv_outstanding_called: Max outstanding called
            proposed_data_structure_nesting_level: Nesting level
            init_request_detail: Optional InitRequestDetail

        Returns:
            BER-encoded Initiate-RequestPDU
        """
        items = []

        # [0] localDetailCalling (optional)
        if local_detail_calling is not None:
            items.append(
                self.build_context_specific(
                    0, self._encode_integer_content(local_detail_calling), constructed=False
                )
            )

        # [1] proposedMaxServOutstandingCalling
        items.append(
            self.build_context_specific(
                1,
                self._encode_integer_content(proposed_max_serv_outstanding_calling),
                constructed=False,
            )
        )

        # [2] proposedMaxServOutstandingCalled
        items.append(
            self.build_context_specific(
                2,
                self._encode_integer_content(proposed_max_serv_outstanding_called),
                constructed=False,
            )
        )

        # [3] proposedDataStructureNestingLevel (optional)
        if proposed_data_structure_nesting_level is not None:
            items.append(
                self.build_context_specific(
                    3,
                    self._encode_integer_content(proposed_data_structure_nesting_level),
                    constructed=False,
                )
            )

        # [4] mmsInitRequestDetail (optional)
        if init_request_detail is not None:
            items.append(self.build_context_specific(4, init_request_detail, constructed=True))
        else:
            # Default InitRequestDetail
            items.append(
                self.build_context_specific(
                    4, self._build_default_init_request_detail(), constructed=True
                )
            )

        content = b"".join(items)
        return self.build_context_specific(8, content, constructed=True)

    # =========================================================================
    # Service Request Builders
    # =========================================================================

    def build_identify_request(self) -> bytes:
        """
        Build an Identify service request.

        Structure:
            identify [2] IMPLICIT NULL

        Returns:
            BER-encoded Identify request
        """
        invoke_id = self.next_invoke_id()
        # Identify is NULL
        service = self.build_context_specific(MMSServiceType.IDENTIFY, b"", constructed=False)
        return self.build_confirmed_request(invoke_id, service)

    def build_get_name_list_request(
        self,
        object_class: int = MMSObjectClass.NAMED_VARIABLE,
        object_scope: Optional[str] = None,
        continue_after: Optional[str] = None,
    ) -> bytes:
        """
        Build a GetNameList service request.

        Structure:
            getNameList [1] IMPLICIT SEQUENCE {
                extendedObjectClass [0] ObjectClass,
                objectScope         ObjectScope,
                continueAfter       [2] IMPLICIT Identifier OPTIONAL
            }

        Args:
            object_class: Type of objects to list
            object_scope: Scope (None for VMD-specific, string for domain)
            continue_after: Continue listing after this identifier

        Returns:
            BER-encoded GetNameList request
        """
        invoke_id = self.next_invoke_id()

        items = []

        # [0] extendedObjectClass
        object_class_enc = self.build_context_specific(
            0, self.build_integer(object_class)[2:], constructed=False
        )
        items.append(self.build_context_specific(0, object_class_enc, constructed=True))

        # objectScope - choice
        if object_scope is None:
            # vmdSpecific [0] NULL
            items.append(self.build_context_specific(0, b"", constructed=False))
        else:
            # domainSpecific [1] Identifier
            items.append(
                self.build_context_specific(
                    1, self.build_visible_string(object_scope)[2:], constructed=False
                )
            )

        # [2] continueAfter (optional)
        if continue_after is not None:
            items.append(
                self.build_context_specific(2, continue_after.encode("ascii"), constructed=False)
            )

        content = b"".join(items)
        service = self.build_context_specific(
            MMSServiceType.GET_NAME_LIST, content, constructed=True
        )
        return self.build_confirmed_request(invoke_id, service)

    def build_read_request(
        self,
        variable_specs: List[Tuple[str, Optional[str]]],
        specification_with_result: bool = False,
    ) -> bytes:
        """
        Build a Read service request.

        Args:
            variable_specs: List of (name, domain) tuples
            specification_with_result: Include spec in response

        Returns:
            BER-encoded Read request
        """
        invoke_id = self.next_invoke_id()

        items = []

        # [0] specificationWithResult (optional, default FALSE)
        if specification_with_result:
            items.append(self.build_context_specific(0, bytes([0xFF]), constructed=False))

        # variableAccessSpecification
        var_list = []
        for name, domain in variable_specs:
            var_list.append(self._build_variable_specification(name, domain))

        # listOfVariable [0]
        var_list_seq = self.build_sequence(*var_list)
        items.append(self.build_context_specific(0, var_list_seq[2:], constructed=True))

        content = b"".join(items)
        service = self.build_context_specific(MMSServiceType.READ, content, constructed=True)
        return self.build_confirmed_request(invoke_id, service)

    def build_write_request(
        self, variable_specs: List[Tuple[str, Optional[str]]], data: List[bytes]
    ) -> bytes:
        """
        Build a Write service request.

        Args:
            variable_specs: List of (name, domain) tuples
            data: List of encoded Data values

        Returns:
            BER-encoded Write request
        """
        invoke_id = self.next_invoke_id()

        # variableAccessSpecification
        var_list = []
        for name, domain in variable_specs:
            var_list.append(self._build_variable_specification(name, domain))

        var_list_seq = self.build_sequence(*var_list)
        var_spec = self.build_context_specific(0, var_list_seq[2:], constructed=True)

        # listOfData
        data_seq = self.build_sequence(*data)
        data_list = self.build_context_specific(0, data_seq[2:], constructed=True)

        content = var_spec + data_list
        service = self.build_context_specific(MMSServiceType.WRITE, content, constructed=True)
        return self.build_confirmed_request(invoke_id, service)

    # =========================================================================
    # MMS Data Type Builders
    # =========================================================================

    def build_mms_boolean(self, value: bool) -> bytes:
        """Build MMS Boolean data."""
        return self.build_context_specific(3, bytes([0xFF if value else 0x00]), constructed=False)

    # =========================================================================
    # Helper Methods
    # =========================================================================

    def _encode_integer_content(self, value: int) -> bytes:
        """Encode integer value without tag/length."""
        if value == 0:
            return bytes([0x00])

        octets = []
        if value > 0:
            n = value
            while n > 0:
                octets.insert(0, n & 0xFF)
                n >>= 8
            if octets[0] & 0x80:
                octets.insert(0, 0x00)
        else:
            n = value
            while True:
                octets.insert(0, n & 0xFF)
                n >>= 8
                if n == -1 and octets[0] & 0x80:
                    break
                if n == 0 and not (octets[0] & 0x80):
                    break

        return bytes(octets)

    def _build_variable_specification(self, name: str, domain: Optional[str]) -> bytes:
        """
        Build a VariableSpecification.

        Args:
            name: Variable name
            domain: Domain name (None for VMD-specific)

        Returns:
            BER-encoded VariableSpecification
        """
        # name [0] ObjectName
        if domain is None:
            # vmdSpecific [0]
            name_enc = self.build_context_specific(0, name.encode("ascii"), constructed=False)
        else:
            # domainSpecific [1] SEQUENCE { domainId, itemId }
            domain_seq = self.build_sequence(
                self.build_visible_string(domain), self.build_visible_string(name)
            )
            name_enc = self.build_context_specific(1, domain_seq[2:], constructed=True)

        return self.build_context_specific(0, name_enc, constructed=True)

    def _build_default_init_request_detail(self) -> bytes:
        """
        Build default InitRequestDetail.

        Structure:
            InitRequestDetail ::= SEQUENCE {
                proposedVersionNumber     [0] IMPLICIT Integer16,
                proposedParameterCBB      [1] IMPLICIT ParameterSupportOptions,
                servicesSupportedCalling  [2] IMPLICIT ServiceSupportOptions
            }
        """
        items = []

        # [0] proposedVersionNumber (1 = MMS-1, 2 = MMS-2)
        items.append(self.build_context_specific(0, bytes([0x01, 0x01]), constructed=False))

        # [1] proposedParameterCBB - bit string of supported parameters
        # All zeros for basic support
        items.append(self.build_context_specific(1, bytes([0x00] * 12), constructed=False))

        # [2] servicesSupportedCalling - bit string of services
        # Enable basic services (status, getNameList, identify, read, write)
        services_bitmap = bytes(
            [
                0x00,  # padding bits
                0xEE,
                0x1C,
                0x00,
                0x00,
                0x04,
                0x08,
                0x00,
                0x00,
                0x01,
                0x00,
                0x00,
            ]
        )
        items.append(self.build_context_specific(2, services_bitmap, constructed=False))

        return b"".join(items)


# Convenience singleton
mms = MMSCodec()
