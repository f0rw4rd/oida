"""OPC UA Protocol Constants

Contains all OPC UA constant classes for message types, security policies,
node IDs, service IDs, and other protocol-specific enumerations.
"""


class OPCUAMessageTypes:
    """OPC UA message type identifiers (3 bytes ASCII)"""

    HELLO = b"HEL"
    ACKNOWLEDGE = b"ACK"
    ERROR = b"ERR"
    REVERSE_HELLO = b"RHE"
    OPEN_SECURE_CHANNEL = b"OPN"
    CLOSE_SECURE_CHANNEL = b"CLO"
    MESSAGE = b"MSG"


class OPCUASecurityPolicies:
    """OPC UA security policy URIs"""

    NONE = "http://opcfoundation.org/UA/SecurityPolicy#None"
    BASIC128RSA15 = "http://opcfoundation.org/UA/SecurityPolicy#Basic128Rsa15"
    BASIC256 = "http://opcfoundation.org/UA/SecurityPolicy#Basic256"
    BASIC256SHA256 = "http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256"
    AES128_SHA256_RSAOAEP = "http://opcfoundation.org/UA/SecurityPolicy#Aes128_Sha256_RsaOaep"
    AES256_SHA256_RSAPSS = "http://opcfoundation.org/UA/SecurityPolicy#Aes256_Sha256_RsaPss"


class OPCUANodeIdTypes:
    """OPC UA NodeId encoding types"""

    TWO_BYTE = 0x00  # Numeric, namespace 0, id 0-255
    FOUR_BYTE = 0x01  # Numeric, namespace 0-255, id 0-65535
    NUMERIC = 0x02  # Numeric, any namespace, any id
    STRING = 0x03  # String identifier
    GUID = 0x04  # GUID identifier
    BYTE_STRING = 0x05  # ByteString identifier


class OPCUAServiceIds:
    """OPC UA Service Request/Response TypeIds (NodeId identifiers)

    These are the _Encoding_DefaultBinary NodeId values used in the OPC UA
    binary protocol. Each service type has a base ID, and the binary encoding
    ID is base + 2 (for encoding) or commonly referenced as the standardized
    binary encoding identifier.
    """

    # Connection Services (no security)
    HELLO = 0  # Custom - not a real service ID

    # Discovery Services (_Encoding_DefaultBinary values)
    FIND_SERVERS_REQUEST = 422
    FIND_SERVERS_RESPONSE = 425
    FIND_SERVERS_ON_NETWORK_REQUEST = 12208
    FIND_SERVERS_ON_NETWORK_RESPONSE = 12209
    GET_ENDPOINTS_REQUEST = 428
    GET_ENDPOINTS_RESPONSE = 431
    REGISTER_SERVER_REQUEST = 437
    REGISTER_SERVER_RESPONSE = 440
    REGISTER_SERVER2_REQUEST = 12211
    REGISTER_SERVER2_RESPONSE = 12212

    # SecureChannel Services
    OPEN_SECURE_CHANNEL_REQUEST = 446
    OPEN_SECURE_CHANNEL_RESPONSE = 449
    CLOSE_SECURE_CHANNEL_REQUEST = 452
    CLOSE_SECURE_CHANNEL_RESPONSE = 455

    # Session Services
    CREATE_SESSION_REQUEST = 461
    CREATE_SESSION_RESPONSE = 464
    ACTIVATE_SESSION_REQUEST = 467
    ACTIVATE_SESSION_RESPONSE = 470
    CLOSE_SESSION_REQUEST = 473
    CLOSE_SESSION_RESPONSE = 476
    CANCEL_REQUEST = 479
    CANCEL_RESPONSE = 482

    # Node Management Services
    ADD_NODES_REQUEST = 488
    ADD_NODES_RESPONSE = 491
    ADD_REFERENCES_REQUEST = 494
    ADD_REFERENCES_RESPONSE = 497
    DELETE_NODES_REQUEST = 500
    DELETE_NODES_RESPONSE = 503
    DELETE_REFERENCES_REQUEST = 506
    DELETE_REFERENCES_RESPONSE = 509

    # View Services
    BROWSE_REQUEST = 527
    BROWSE_RESPONSE = 530
    BROWSE_NEXT_REQUEST = 533
    BROWSE_NEXT_RESPONSE = 536
    TRANSLATE_BROWSE_PATHS_REQUEST = 554
    TRANSLATE_BROWSE_PATHS_RESPONSE = 557
    REGISTER_NODES_REQUEST = 560
    REGISTER_NODES_RESPONSE = 563
    UNREGISTER_NODES_REQUEST = 566
    UNREGISTER_NODES_RESPONSE = 569

    # Query Services
    QUERY_FIRST_REQUEST = 615
    QUERY_FIRST_RESPONSE = 618
    QUERY_NEXT_REQUEST = 621
    QUERY_NEXT_RESPONSE = 624

    # Attribute Services
    READ_REQUEST = 631
    READ_RESPONSE = 634
    HISTORY_READ_REQUEST = 664
    HISTORY_READ_RESPONSE = 667
    WRITE_REQUEST = 673
    WRITE_RESPONSE = 676
    HISTORY_UPDATE_REQUEST = 700
    HISTORY_UPDATE_RESPONSE = 703

    # Method Services
    CALL_REQUEST = 712
    CALL_RESPONSE = 715

    # MonitoredItem Services
    CREATE_MONITORED_ITEMS_REQUEST = 751
    CREATE_MONITORED_ITEMS_RESPONSE = 754
    MODIFY_MONITORED_ITEMS_REQUEST = 763
    MODIFY_MONITORED_ITEMS_RESPONSE = 766
    SET_MONITORING_MODE_REQUEST = 769
    SET_MONITORING_MODE_RESPONSE = 772
    SET_TRIGGERING_REQUEST = 775
    SET_TRIGGERING_RESPONSE = 778
    DELETE_MONITORED_ITEMS_REQUEST = 781
    DELETE_MONITORED_ITEMS_RESPONSE = 784

    # Subscription Services
    CREATE_SUBSCRIPTION_REQUEST = 787
    CREATE_SUBSCRIPTION_RESPONSE = 790
    MODIFY_SUBSCRIPTION_REQUEST = 793
    MODIFY_SUBSCRIPTION_RESPONSE = 796
    SET_PUBLISHING_MODE_REQUEST = 799
    SET_PUBLISHING_MODE_RESPONSE = 802
    PUBLISH_REQUEST = 826
    PUBLISH_RESPONSE = 829
    REPUBLISH_REQUEST = 832
    REPUBLISH_RESPONSE = 835
    TRANSFER_SUBSCRIPTIONS_REQUEST = 841
    TRANSFER_SUBSCRIPTIONS_RESPONSE = 844
    DELETE_SUBSCRIPTIONS_REQUEST = 847
    DELETE_SUBSCRIPTIONS_RESPONSE = 850


class OPCUASecurityTokenRequestType:
    """Security token request types"""

    ISSUE = 0
    RENEW = 1


class OPCUAMessageSecurityMode:
    """Message security modes"""

    INVALID = 0
    NONE = 1
    SIGN = 2
    SIGN_AND_ENCRYPT = 3


class OPCUATimestampsToReturn:
    """Timestamps to return in read operations"""

    SOURCE = 0
    SERVER = 1
    BOTH = 2
    NEITHER = 3


class OPCUABrowseDirection:
    """Browse directions"""

    FORWARD = 0
    INVERSE = 1
    BOTH = 2


__all__ = [
    "OPCUAMessageTypes",
    "OPCUASecurityPolicies",
    "OPCUANodeIdTypes",
    "OPCUAServiceIds",
    "OPCUASecurityTokenRequestType",
    "OPCUAMessageSecurityMode",
    "OPCUATimestampsToReturn",
    "OPCUABrowseDirection",
]
