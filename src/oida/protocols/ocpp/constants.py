"""
OCPP Protocol Constants and Enumerations

This module contains all OCPP-related constants, enums, and lookup tables
used throughout the OCPP scanner implementation.
"""

from enum import IntEnum, Enum


# OCPP-J message type IDs
class MessageType(IntEnum):
    """OCPP-J message type identifiers"""

    CALL = 2  # Request
    CALLRESULT = 3  # Response
    CALLERROR = 4  # Error response


class OCPPVersion(str, Enum):
    """Supported OCPP versions"""

    V16 = "ocpp1.6"
    V20 = "ocpp2.0"
    V201 = "ocpp2.0.1"
    V21 = "ocpp2.1"


# WebSocket subprotocol identifiers
OCPP_SUBPROTOCOLS = {
    "1.6": "ocpp1.6",
    "2.0": "ocpp2.0",
    "2.0.1": "ocpp2.0.1",
    "2.1": "ocpp2.1",
}

# Mapping from subprotocol to version string
SUBPROTOCOL_TO_VERSION = {v: k for k, v in OCPP_SUBPROTOCOLS.items()}


class SecurityProfile(IntEnum):
    """OCPP security profiles (1.6 Security Whitepaper / 2.0.1 Part 2)"""

    NONE = 0  # No security, ws:// without authentication
    BASIC_AUTH = 1  # HTTP Basic Authentication over ws://
    CLIENT_CERT_TLS = 2  # TLS with client-side certificates (wss://)
    TLS_WITH_CSMS_CERT = 3  # TLS with CSMS certificate + client cert (wss://)


SECURITY_PROFILE_NAMES = {
    SecurityProfile.NONE: "No Security (Profile 0)",
    SecurityProfile.BASIC_AUTH: "HTTP Basic Auth (Profile 1)",
    SecurityProfile.CLIENT_CERT_TLS: "TLS + Client Certificate (Profile 2)",
    SecurityProfile.TLS_WITH_CSMS_CERT: "TLS + CSMS & Client Certificate (Profile 3)",
}


class ChargePointStatus(str, Enum):
    """Charge point connector status values (OCPP 1.6)"""

    AVAILABLE = "Available"
    PREPARING = "Preparing"
    CHARGING = "Charging"
    SUSPENDED_EVSE = "SuspendedEVSE"
    SUSPENDED_EV = "SuspendedEV"
    FINISHING = "Finishing"
    RESERVED = "Reserved"
    UNAVAILABLE = "Unavailable"
    FAULTED = "Faulted"


class RegistrationStatus(str, Enum):
    """BootNotification response status"""

    ACCEPTED = "Accepted"
    PENDING = "Pending"
    REJECTED = "Rejected"


class ErrorCode(str, Enum):
    """OCPP-J CALLERROR error codes"""

    NOT_IMPLEMENTED = "NotImplemented"
    NOT_SUPPORTED = "NotSupported"
    INTERNAL_ERROR = "InternalError"
    PROTOCOL_ERROR = "ProtocolError"
    SECURITY_ERROR = "SecurityError"
    FORMATION_VIOLATION = "FormationViolation"
    PROPERTY_CONSTRAINT_VIOLATION = "PropertyConstraintViolation"
    OCCURRENCE_CONSTRAINT_VIOLATION = "OccurrenceConstraintViolation"
    TYPE_CONSTRAINT_VIOLATION = "TypeConstraintViolation"
    GENERIC_ERROR = "GenericError"


# OCPP-J error code descriptions
ERROR_CODE_DESCRIPTIONS = {
    "NotImplemented": "Requested Action is not known by receiver",
    "NotSupported": "Requested Action is recognized but not supported by receiver",
    "InternalError": "An internal error occurred on the receiver side",
    "ProtocolError": "Payload for Action is incomplete or syntactically incorrect",
    "SecurityError": "During security validation an error occurred",
    "FormationViolation": "Payload for Action is syntactically incorrect",
    "PropertyConstraintViolation": "Payload is syntactically correct but field violates constraints",
    "OccurrenceConstraintViolation": "Payload missing required field or has too many instances",
    "TypeConstraintViolation": "Payload field has wrong data type",
    "GenericError": "Any other error not covered by the more specific error codes",
}


# ============================================================================
# OCPP 1.6 Actions
# ============================================================================

# Actions initiated by Charge Point -> Central System
CP_INITIATED_ACTIONS_V16 = [
    "Authorize",
    "BootNotification",
    "DataTransfer",
    "DiagnosticsStatusNotification",
    "FirmwareStatusNotification",
    "Heartbeat",
    "MeterValues",
    "StartTransaction",
    "StatusNotification",
    "StopTransaction",
]

# Actions initiated by Central System -> Charge Point
CS_INITIATED_ACTIONS_V16 = [
    "CancelReservation",
    "ChangeAvailability",
    "ChangeConfiguration",
    "ClearCache",
    "ClearChargingProfile",
    "DataTransfer",
    "GetCompositeSchedule",
    "GetConfiguration",
    "GetDiagnostics",
    "GetLocalListVersion",
    "RemoteStartTransaction",
    "RemoteStopTransaction",
    "ReserveNow",
    "Reset",
    "SendLocalList",
    "SetChargingProfile",
    "TriggerMessage",
    "UnlockConnector",
    "UpdateFirmware",
]

# All OCPP 1.6 actions combined
ALL_ACTIONS_V16 = sorted(set(CP_INITIATED_ACTIONS_V16 + CS_INITIATED_ACTIONS_V16))


# ============================================================================
# OCPP 2.0.1 Actions (subset of key additions over 1.6)
# ============================================================================

CP_INITIATED_ACTIONS_V201 = [
    "Authorize",
    "BootNotification",
    "ClearedChargingLimit",
    "DataTransfer",
    "FirmwareStatusNotification",
    "Get15118EVCertificate",
    "GetCertificateStatus",
    "Heartbeat",
    "LogStatusNotification",
    "MeterValues",
    "NotifyChargingLimit",
    "NotifyCustomerInformation",
    "NotifyDisplayMessages",
    "NotifyEVChargingNeeds",
    "NotifyEVChargingSchedule",
    "NotifyEvent",
    "NotifyMonitoringReport",
    "NotifyReport",
    "PublishFirmwareStatusNotification",
    "ReportChargingProfiles",
    "RequestStartTransaction",
    "RequestStopTransaction",
    "ReservationStatusUpdate",
    "SecurityEventNotification",
    "SignCertificate",
    "StatusNotification",
    "TransactionEvent",
]

CS_INITIATED_ACTIONS_V201 = [
    "CancelReservation",
    "CertificateSigned",
    "ChangeAvailability",
    "ClearCache",
    "ClearChargingProfile",
    "ClearDisplayMessage",
    "ClearVariableMonitoring",
    "CostUpdated",
    "CustomerInformation",
    "DataTransfer",
    "DeleteCertificate",
    "GetBaseReport",
    "GetChargingProfiles",
    "GetCompositeSchedule",
    "GetDisplayMessages",
    "GetInstalledCertificateIds",
    "GetLocalListVersion",
    "GetLog",
    "GetMonitoringReport",
    "GetReport",
    "GetTransactionStatus",
    "GetVariables",
    "InstallCertificate",
    "PublishFirmware",
    "RequestStartTransaction",
    "RequestStopTransaction",
    "ReserveNow",
    "Reset",
    "SendLocalList",
    "SetChargingProfile",
    "SetDisplayMessage",
    "SetMonitoringBase",
    "SetMonitoringLevel",
    "SetNetworkProfile",
    "SetVariableMonitoring",
    "SetVariables",
    "TriggerMessage",
    "UnlockConnector",
    "UnpublishFirmware",
    "UpdateFirmware",
]

ALL_ACTIONS_V201 = sorted(set(CP_INITIATED_ACTIONS_V201 + CS_INITIATED_ACTIONS_V201))


# ============================================================================
# Configuration Keys (OCPP 1.6)
# ============================================================================

# Standard configuration keys from OCPP 1.6 specification
CONFIGURATION_KEYS_V16 = [
    # Core Profile
    "AllowOfflineTxForUnknownId",
    "AuthorizationCacheEnabled",
    "AuthorizeRemoteTxRequests",
    "BlinkRepeat",
    "ClockAlignedDataInterval",
    "ConnectionTimeOut",
    "ConnectorPhaseRotation",
    "ConnectorPhaseRotationMaxLength",
    "GetConfigurationMaxKeys",
    "HeartbeatInterval",
    "LightIntensity",
    "LocalAuthorizeOffline",
    "LocalPreAuthorize",
    "MaxEnergyOnInvalidId",
    "MeterValuesAlignedData",
    "MeterValuesAlignedDataMaxLength",
    "MeterValuesSampledData",
    "MeterValuesSampledDataMaxLength",
    "MeterValueSampleInterval",
    "MinimumStatusDuration",
    "NumberOfConnectors",
    "ResetRetries",
    "StopTransactionOnEVSideDisconnect",
    "StopTransactionOnInvalidId",
    "StopTxnAlignedData",
    "StopTxnAlignedDataMaxLength",
    "StopTxnSampledData",
    "StopTxnSampledDataMaxLength",
    "SupportedFeatureProfiles",
    "SupportedFeatureProfilesMaxLength",
    "TransactionMessageAttempts",
    "TransactionMessageRetryInterval",
    "UnlockConnectorOnEVSideDisconnect",
    "WebSocketPingInterval",
    # Local Auth List Management Profile
    "LocalAuthListEnabled",
    "LocalAuthListMaxLength",
    "SendLocalListMaxLength",
    # Reservation Profile
    "ReserveConnectorZeroSupported",
    # Smart Charging Profile
    "ChargeProfileMaxStackLevel",
    "ChargingScheduleAllowedChargingRateUnit",
    "ChargingScheduleMaxPeriods",
    "ConnectorSwitch3to1PhaseSupported",
    "MaxChargingProfilesInstalled",
    # Security
    "AuthorizationKey",
    "CpoName",
    "SecurityProfile",
]

# Security-relevant configuration keys
SECURITY_CONFIG_KEYS = [
    "AuthorizationKey",
    "SecurityProfile",
    "CpoName",
    "SupportedFeatureProfiles",
    "WebSocketPingInterval",
    "AuthorizationCacheEnabled",
    "LocalAuthorizeOffline",
    "LocalPreAuthorize",
    "LocalAuthListEnabled",
]

# Security-sensitive config keys that should not be writable without auth
SENSITIVE_CONFIG_KEYS = [
    "AuthorizationKey",
    "SecurityProfile",
    "AllowOfflineTxForUnknownId",
]

# Harmless config key used to test write access
HARMLESS_CONFIG_KEY = "HeartbeatInterval"


# Dummy/fake values for security probes (clearly non-functional)
FAKE_ID_TAG = "OIDA_SEC_TEST_00000000"
FAKE_FIRMWARE_URL = "http://0.0.0.0/test.bin"
FAKE_FIRMWARE_RETRIEVE_DATE = "2099-01-01T00:00:00.000Z"
FAKE_DIAGNOSTICS_URL = "http://0.0.0.0/diag_upload"
FAKE_LOG_URL = "http://0.0.0.0/log_upload"
SAFE_CHARGING_PROFILE_ID = 99999
SAFE_TRANSACTION_ID = 0
SAFE_CONNECTOR_ID = 1
SAFE_METER_START = 0
SAFE_METER_STOP = 1
SAFE_RESERVATION_ID = 99999

# Network profile redirect test URL (non-routable)
FAKE_NETWORK_PROFILE_URL = "wss://0.0.0.0:443/ocpp/"

# Self-signed test certificate for InstallCertificate probe.
# This is intentionally a fake/invalid PEM used only to test whether the
# charger accepts arbitrary root CA installations without validation.
PROBE_TEST_CERTIFICATE = (
    "-----BEGIN CERTIFICATE-----\nOIDA-SECURITY-TEST-PROBE-CERTIFICATE\n-----END CERTIFICATE-----"
)

# Display message for SetDisplayMessage probe
PROBE_DISPLAY_MESSAGE = "OIDA Security Audit"

# SSRF probe URLs for extended SSRF testing via UpdateFirmware/GetDiagnostics/GetLog
SSRF_PROBE_URLS = [
    ("http://169.254.169.254/latest/meta-data/", "AWS metadata"),
    (
        "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
        "Azure metadata",
    ),
    (
        "http://metadata.google.internal/computeMetadata/v1/",
        "GCP metadata",
    ),
    ("http://127.0.0.1:80/", "localhost"),
    ("file:///etc/passwd", "file URI"),
]


# Maximum number of server-initiated CALLs to handle while waiting for a CALLRESULT
MAX_INCOMING_CALLS_PER_EXCHANGE = 5

# Default heartbeat interval for listen mode (seconds)
# Used when BootNotification doesn't provide an interval
DEFAULT_HEARTBEAT_INTERVAL = 30

# Default ports
DEFAULT_WS_PORT = 9000
DEFAULT_WSS_PORT = 443

# WebSocket URL path pattern (typically /ocpp/<chargePointId> or /<chargePointId>)
DEFAULT_CP_ID = "CP_SCANNER_001"

# Protocol options for scanner registration
PROTOCOL_OPTIONS = {
    "url": {
        "type": "string",
        "description": "OCPP WebSocket URL (e.g., ws://host:9000/CP_001)",
        "required": True,
    },
    "version": {
        "type": "enum",
        "description": "OCPP version to use",
        "values": ["1.6", "2.0.1", "2.1", "auto"],
        "default": "auto",
    },
    "charge-point-id": {
        "type": "string",
        "description": "Charge Point ID for WebSocket path",
        "default": DEFAULT_CP_ID,
    },
    "security-profile": {
        "type": "int",
        "description": "Security profile to test (0-3)",
        "default": 0,
    },
}
