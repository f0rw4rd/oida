"""
OCPP Message Crafting and Parsing Mixin

Provides OCPP-J message construction, parsing, and action probing
for the NXC-style OCPP connection class.
"""

import json
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from ..constants import MessageType


class MessagesMixin:
    """Mixin for OCPP message crafting and parsing"""

    def _generate_message_id(self) -> str:
        """Generate a unique message ID for OCPP-J CALL messages."""
        return str(uuid.uuid4())[:8]

    def _build_call(self, action: str, payload: Optional[Dict[str, Any]] = None) -> str:
        """
        Build an OCPP-J CALL message.

        Args:
            action: OCPP action name (e.g., "BootNotification")
            payload: Action payload dictionary

        Returns:
            JSON-encoded CALL message string
        """
        message_id = self._generate_message_id()
        message = [MessageType.CALL, message_id, action, payload or {}]
        return json.dumps(message)

    def _build_call_result(self, message_id: str, payload: Optional[Dict[str, Any]] = None) -> str:
        """
        Build an OCPP-J CALLRESULT message.

        Args:
            message_id: Original CALL message ID
            payload: Response payload dictionary

        Returns:
            JSON-encoded CALLRESULT message string
        """
        message = [MessageType.CALLRESULT, message_id, payload or {}]
        return json.dumps(message)

    def _build_call_error(
        self,
        message_id: str,
        error_code: str = "GenericError",
        error_description: str = "",
        error_details: Optional[Dict[str, Any]] = None,
    ) -> str:
        """
        Build an OCPP-J CALLERROR message.

        Args:
            message_id: Original CALL message ID
            error_code: OCPP error code string
            error_description: Human-readable error description
            error_details: Optional error details dictionary

        Returns:
            JSON-encoded CALLERROR message string
        """
        message = [
            MessageType.CALLERROR,
            message_id,
            error_code,
            error_description,
            error_details or {},
        ]
        return json.dumps(message)

    def _parse_message(self, raw: str) -> Tuple[int, str, Any]:
        """
        Parse an OCPP-J message.

        Args:
            raw: Raw JSON message string

        Returns:
            Tuple of (message_type, message_id, payload_or_action)
            - For CALL: (2, id, {"action": action, "payload": payload})
            - For CALLRESULT: (3, id, payload)
            - For CALLERROR: (4, id, {"error_code": code, "error_description": desc, "details": details})

        Raises:
            ValueError: If message format is invalid
        """
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON: {e}") from e

        if not isinstance(data, list) or len(data) < 3:
            raise ValueError("Invalid OCPP-J message format: expected list with 3+ elements")

        message_type = data[0]
        message_id = str(data[1])

        if message_type == MessageType.CALL:
            if len(data) < 4:
                raise ValueError("CALL message requires 4 elements")
            return message_type, message_id, {"action": data[2], "payload": data[3]}

        elif message_type == MessageType.CALLRESULT:
            return message_type, message_id, data[2]

        elif message_type == MessageType.CALLERROR:
            if len(data) < 5:
                raise ValueError("CALLERROR message requires 5 elements")
            return (
                message_type,
                message_id,
                {
                    "error_code": data[2],
                    "error_description": data[3],
                    "details": data[4] if len(data) > 4 else {},
                },
            )

        else:
            raise ValueError(f"Unknown message type: {message_type}")

    def _build_boot_notification(self, version: str = "1.6") -> str:
        """
        Build a BootNotification CALL message.

        Args:
            version: OCPP version ("1.6" or "2.0.1")

        Returns:
            JSON-encoded BootNotification CALL message
        """
        args = getattr(self, "args", None)
        vendor = getattr(args, "vendor", None)
        model = getattr(args, "model", None)
        vendor = vendor if isinstance(vendor, str) and vendor else "SecurityAudit"
        model = model if isinstance(model, str) and model else "OIDA-Scanner"
        if version.startswith("2."):
            payload = {
                "reason": "PowerUp",
                "chargingStation": {
                    "model": model,
                    "vendorName": vendor,
                    "serialNumber": "SCAN-001",
                    "firmwareVersion": "1.0.0",
                },
            }
        else:
            # OCPP 1.6
            payload = {
                "chargePointVendor": vendor,
                "chargePointModel": model,
                "chargePointSerialNumber": "SCAN-001",
                "firmwareVersion": "1.0.0",
            }
        return self._build_call("BootNotification", payload)

    def _build_heartbeat(self) -> str:
        """Build a Heartbeat CALL message."""
        return self._build_call("Heartbeat", {})

    def _build_get_configuration(
        self, keys: Optional[List[str]] = None, version: str = "1.6"
    ) -> str:
        """
        Build a GetConfiguration (1.6) or GetVariables (2.0.1) CALL message.

        Args:
            keys: Optional list of configuration key names to query.
                  If None, requests all keys.
            version: OCPP version

        Returns:
            JSON-encoded CALL message
        """
        if version.startswith("2."):
            # OCPP 2.0.1: GetVariables
            if keys:
                get_vars = [
                    {"component": {"name": "OCPPCommCtrlr"}, "variable": {"name": k}} for k in keys
                ]
            else:
                get_vars = [
                    {"component": {"name": "OCPPCommCtrlr"}, "variable": {"name": ""}},
                ]
            return self._build_call("GetVariables", {"getVariableData": get_vars})
        payload = {}
        if keys:
            payload["key"] = keys
        return self._build_call("GetConfiguration", payload)

    def _build_data_transfer(
        self,
        vendor_id: str = "SecurityAudit",
        message_id: Optional[str] = None,
        data: Optional[str] = None,
    ) -> str:
        """
        Build a DataTransfer CALL message.

        Args:
            vendor_id: Vendor identifier string
            message_id: Optional message identifier
            data: Optional data payload string

        Returns:
            JSON-encoded DataTransfer CALL message
        """
        payload = {"vendorId": vendor_id}
        if message_id is not None:
            payload["messageId"] = message_id
        if data is not None:
            payload["data"] = data
        return self._build_call("DataTransfer", payload)

    def _build_status_notification(
        self, connector_id: int = 0, status: str = "Available", error_code: str = "NoError"
    ) -> str:
        """
        Build a StatusNotification CALL message (OCPP 1.6).

        Args:
            connector_id: Connector ID (0 = charge point itself)
            status: Connector status string
            error_code: Error code string

        Returns:
            JSON-encoded StatusNotification CALL message
        """
        payload = {
            "connectorId": connector_id,
            "errorCode": error_code,
            "status": status,
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
        }
        return self._build_call("StatusNotification", payload)

    def _build_trigger_message(self, requested_message: str, connector_id: int = 0) -> str:
        """
        Build a TriggerMessage CALL message (CS -> CP, OCPP 1.6).

        This requests the Charge Point to send a specific message.

        Args:
            requested_message: Message type to trigger
            connector_id: Optional connector ID

        Returns:
            JSON-encoded TriggerMessage CALL message
        """
        payload = {"requestedMessage": requested_message}
        if connector_id > 0:
            payload["connectorId"] = connector_id
        return self._build_call("TriggerMessage", payload)

    def _build_remote_start_transaction(
        self, id_tag: str, connector_id: int = 1, version: str = "1.6"
    ) -> str:
        """
        Build a RemoteStartTransaction (1.6) or RequestStartTransaction (2.0.1).

        Args:
            id_tag: Authorization ID tag (RFID token)
            connector_id: Target connector ID
            version: OCPP version

        Returns:
            JSON-encoded CALL message
        """
        if version.startswith("2."):
            payload = {
                "idToken": {"idToken": id_tag, "type": "ISO14443"},
                "evseId": connector_id,
            }
            return self._build_call("RequestStartTransaction", payload)
        payload = {"idTag": id_tag, "connectorId": connector_id}
        return self._build_call("RemoteStartTransaction", payload)

    def _build_reset(self, reset_type: str = "Soft", version: str = "1.6") -> str:
        """
        Build a Reset CALL message (CS -> CP).

        Args:
            reset_type: 1.6: "Soft"/"Hard", 2.0.1: "OnIdle"/"Immediate"
                        If a 1.6 type is passed with a 2.0.1 version, it is mapped automatically.
            version: OCPP version

        Returns:
            JSON-encoded Reset CALL message
        """
        if version.startswith("2."):
            type_map = {"Soft": "OnIdle", "Hard": "Immediate"}
            reset_type = type_map.get(reset_type, reset_type)
        payload = {"type": reset_type}
        return self._build_call("Reset", payload)

    def _build_unlock_connector(self, connector_id: int = 1, version: str = "1.6") -> str:
        """
        Build an UnlockConnector CALL message (CS -> CP).

        Args:
            connector_id: Connector to unlock
            version: OCPP version

        Returns:
            JSON-encoded UnlockConnector CALL message
        """
        if version.startswith("2."):
            payload = {"evseId": connector_id, "connectorId": 1}
        else:
            payload = {"connectorId": connector_id}
        return self._build_call("UnlockConnector", payload)

    def _build_update_firmware(
        self, location: str, retrieve_date: str, retries: int = 0, version: str = "1.6"
    ) -> str:
        """
        Build an UpdateFirmware CALL message (CS -> CP).

        Args:
            location: Firmware download URL
            retrieve_date: ISO 8601 datetime to retrieve firmware
            retries: Number of retry attempts
            version: OCPP version

        Returns:
            JSON-encoded UpdateFirmware CALL message
        """
        if version.startswith("2."):
            payload = {
                "requestId": 1,
                "firmware": {
                    "location": location,
                    "retrieveDateTime": retrieve_date,
                },
                "retries": retries,
            }
        else:
            payload = {
                "location": location,
                "retrieveDate": retrieve_date,
                "retries": retries,
            }
        return self._build_call("UpdateFirmware", payload)

    def _build_set_charging_profile(
        self,
        connector_id: int,
        profile_id: int,
        stack_level: int = 0,
        purpose: str = "TxDefaultProfile",
        rate_unit: str = "A",
        limit: float = 1.0,
    ) -> str:
        """
        Build a SetChargingProfile CALL message (CS -> CP, OCPP 1.6).

        Args:
            connector_id: Target connector ID
            profile_id: Unique charging profile ID
            stack_level: Stack level for profile priority
            purpose: Charging profile purpose type
            rate_unit: "A" (amps) or "W" (watts)
            limit: Charging rate limit value

        Returns:
            JSON-encoded SetChargingProfile CALL message
        """
        payload = {
            "connectorId": connector_id,
            "csChargingProfiles": {
                "chargingProfileId": profile_id,
                "stackLevel": stack_level,
                "chargingProfilePurpose": purpose,
                "chargingProfileKind": "Absolute",
                "chargingSchedule": {
                    "chargingRateUnit": rate_unit,
                    "chargingSchedulePeriod": [
                        {"startPeriod": 0, "limit": limit},
                    ],
                },
            },
        }
        return self._build_call("SetChargingProfile", payload)

    def _build_clear_charging_profile(
        self,
        profile_id: Optional[int] = None,
        connector_id: Optional[int] = None,
        purpose: Optional[str] = None,
    ) -> str:
        """
        Build a ClearChargingProfile CALL message (CS -> CP, OCPP 1.6).

        Args:
            profile_id: Optional profile ID to clear
            connector_id: Optional connector ID filter
            purpose: Optional charging profile purpose filter

        Returns:
            JSON-encoded ClearChargingProfile CALL message
        """
        payload = {}
        if profile_id is not None:
            payload["id"] = profile_id
        if connector_id is not None:
            payload["connectorId"] = connector_id
        if purpose is not None:
            payload["chargingProfilePurpose"] = purpose
        return self._build_call("ClearChargingProfile", payload)

    def _build_change_configuration(self, key: str, value: str, version: str = "1.6") -> str:
        """
        Build a ChangeConfiguration (1.6) or SetVariables (2.0.1) CALL message.

        Args:
            key: Configuration key name
            value: New value for the key
            version: OCPP version

        Returns:
            JSON-encoded CALL message
        """
        if version.startswith("2."):
            payload = {
                "setVariableData": [
                    {
                        "component": {"name": "OCPPCommCtrlr"},
                        "variable": {"name": key},
                        "attributeValue": value,
                    }
                ]
            }
            return self._build_call("SetVariables", payload)
        payload = {"key": key, "value": value}
        return self._build_call("ChangeConfiguration", payload)

    def _build_get_base_report(
        self, request_id: int = 1, report_base: str = "FullInventory"
    ) -> str:
        """
        Build a GetBaseReport CALL message (CS -> CP, OCPP 2.0.1).

        Args:
            request_id: Unique request ID
            report_base: Report base type ("FullInventory" or "ConfigurationInventory")

        Returns:
            JSON-encoded GetBaseReport CALL message
        """
        payload = {"requestId": request_id, "reportBase": report_base}
        return self._build_call("GetBaseReport", payload)

    def _build_change_availability(
        self, connector_id: int = 0, availability_type: str = "Inoperative", version: str = "1.6"
    ) -> str:
        """
        Build a ChangeAvailability CALL message (CS -> CP).

        Args:
            connector_id: Target connector/EVSE ID (0 = entire charge point)
            availability_type: "Operative" or "Inoperative"
            version: OCPP version

        Returns:
            JSON-encoded ChangeAvailability CALL message
        """
        if version.startswith("2."):
            payload = {"operationalStatus": availability_type}
            if connector_id > 0:
                payload["evse"] = {"id": connector_id}
        else:
            payload = {"connectorId": connector_id, "type": availability_type}
        return self._build_call("ChangeAvailability", payload)

    def _build_clear_cache(self) -> str:
        """
        Build a ClearCache CALL message (CS -> CP).

        Returns:
            JSON-encoded ClearCache CALL message
        """
        return self._build_call("ClearCache", {})

    def _build_get_diagnostics(
        self,
        location: str,
        start_time: Optional[str] = None,
        stop_time: Optional[str] = None,
        retries: int = 0,
    ) -> str:
        """
        Build a GetDiagnostics CALL message (CS -> CP, OCPP 1.6).

        Args:
            location: Upload URL for diagnostics file
            start_time: Optional start of log period (ISO 8601)
            stop_time: Optional end of log period (ISO 8601)
            retries: Number of retry attempts

        Returns:
            JSON-encoded GetDiagnostics CALL message
        """
        payload = {"location": location, "retries": retries}
        if start_time:
            payload["startTime"] = start_time
        if stop_time:
            payload["stopTime"] = stop_time
        return self._build_call("GetDiagnostics", payload)

    def _build_get_log(
        self,
        log_type: str = "DiagnosticsLog",
        request_id: int = 1,
        location: str = "",
        retries: int = 0,
    ) -> str:
        """
        Build a GetLog CALL message (CS -> CP, OCPP 2.0.1).

        Args:
            log_type: "DiagnosticsLog" or "SecurityLog"
            request_id: Unique request ID
            location: Upload URL for log file
            retries: Number of retry attempts

        Returns:
            JSON-encoded GetLog CALL message
        """
        payload = {
            "logType": log_type,
            "requestId": request_id,
            "log": {"remoteLocation": location},
            "retries": retries,
        }
        return self._build_call("GetLog", payload)

    def _build_remote_stop_transaction(self, transaction_id: int, version: str = "1.6") -> str:
        """
        Build a RemoteStopTransaction (1.6) or RequestStopTransaction (2.0.1).

        Args:
            transaction_id: Transaction ID to stop
            version: OCPP version

        Returns:
            JSON-encoded CALL message
        """
        if version.startswith("2."):
            payload = {"transactionId": str(transaction_id)}
            return self._build_call("RequestStopTransaction", payload)
        payload = {"transactionId": transaction_id}
        return self._build_call("RemoteStopTransaction", payload)

    def _build_get_local_list_version(self) -> str:
        """
        Build a GetLocalListVersion CALL message (CS -> CP).

        Returns:
            JSON-encoded GetLocalListVersion CALL message
        """
        return self._build_call("GetLocalListVersion", {})

    def _build_send_local_list(
        self,
        list_version: int = 1,
        update_type: str = "Full",
        local_auth_list: Optional[List[Dict[str, Any]]] = None,
        version: str = "1.6",
    ) -> str:
        """
        Build a SendLocalList CALL message (CS -> CP).

        Args:
            list_version: Version number of the list
            update_type: "Full" or "Differential"
            local_auth_list: List of authorization entries
            version: OCPP version

        Returns:
            JSON-encoded SendLocalList CALL message
        """
        if version.startswith("2."):
            payload = {"versionNumber": list_version, "updateType": update_type}
            if local_auth_list:
                payload["localAuthorizationList"] = local_auth_list
        else:
            payload = {"listVersion": list_version, "updateType": update_type}
            if local_auth_list:
                payload["localAuthorizationList"] = local_auth_list
        return self._build_call("SendLocalList", payload)

    def _build_reserve_now(
        self,
        connector_id: int = 1,
        expiry_date: Optional[str] = None,
        id_tag: str = "",
        reservation_id: int = 99999,
        version: str = "1.6",
    ) -> str:
        """
        Build a ReserveNow CALL message (CS -> CP).

        Args:
            connector_id: Connector/EVSE to reserve
            expiry_date: Reservation expiry (ISO 8601)
            id_tag: Authorization ID tag
            reservation_id: Unique reservation ID
            version: OCPP version

        Returns:
            JSON-encoded ReserveNow CALL message
        """
        if expiry_date is None:
            expiry_date = "2099-01-01T00:00:00.000Z"
        if version.startswith("2."):
            payload = {
                "id": reservation_id,
                "expiryDateTime": expiry_date,
                "idToken": {"idToken": id_tag, "type": "ISO14443"},
            }
            if connector_id > 0:
                payload["evseId"] = connector_id
        else:
            payload = {
                "connectorId": connector_id,
                "expiryDate": expiry_date,
                "idTag": id_tag,
                "reservationId": reservation_id,
            }
        return self._build_call("ReserveNow", payload)

    def _build_cancel_reservation(self, reservation_id: int) -> str:
        """
        Build a CancelReservation CALL message (CS -> CP).

        Args:
            reservation_id: Reservation ID to cancel

        Returns:
            JSON-encoded CancelReservation CALL message
        """
        payload = {"reservationId": reservation_id}
        return self._build_call("CancelReservation", payload)

    def _build_get_composite_schedule(self, connector_id: int = 1, duration: int = 3600) -> str:
        """
        Build a GetCompositeSchedule CALL message (CS -> CP).

        Args:
            connector_id: Target connector ID
            duration: Duration in seconds for the schedule

        Returns:
            JSON-encoded GetCompositeSchedule CALL message
        """
        payload = {"connectorId": connector_id, "duration": duration}
        return self._build_call("GetCompositeSchedule", payload)

    def _build_get_installed_certificate_ids(self, certificate_type: Optional[str] = None) -> str:
        """
        Build a GetInstalledCertificateIds CALL message (CS -> CP, OCPP 2.0.1).

        Args:
            certificate_type: Optional certificate type filter

        Returns:
            JSON-encoded GetInstalledCertificateIds CALL message
        """
        payload = {}
        if certificate_type:
            payload["certificateType"] = [certificate_type]
        return self._build_call("GetInstalledCertificateIds", payload)

    # ==================================================================
    # OCPP 2.0.1 Security / Certificate / Display Messages
    # ==================================================================

    def _build_set_network_profile(
        self,
        configuration_slot: int = 1,
        ocpp_csms_url: str = "",
        security_profile: int = 1,
    ) -> str:
        """
        Build a SetNetworkProfile CALL message (CS -> CP, OCPP 2.0.1).

        Args:
            configuration_slot: Network configuration slot number
            ocpp_csms_url: CSMS WebSocket URL to configure
            security_profile: Security profile index (0-3)

        Returns:
            JSON-encoded SetNetworkProfile CALL message
        """
        payload = {
            "configurationSlot": configuration_slot,
            "connectionData": {
                "ocppVersion": "OCPP20",
                "ocppTransport": "JSON",
                "ocppCsmsUrl": ocpp_csms_url,
                "messageTimeout": 30,
                "securityProfile": security_profile,
                "ocppInterface": "Wired0",
            },
        }
        return self._build_call("SetNetworkProfile", payload)

    def _build_install_certificate(
        self,
        certificate_type: str = "CSMSRootCertificate",
        certificate_pem: str = "",
    ) -> str:
        """
        Build an InstallCertificate CALL message (CS -> CP, OCPP 2.0.1).

        Args:
            certificate_type: One of "CSMSRootCertificate", "V2GRootCertificate",
                "ManufacturerRootCertificate", "MORootCertificate"
            certificate_pem: PEM-encoded certificate string

        Returns:
            JSON-encoded InstallCertificate CALL message
        """
        payload = {
            "certificateType": certificate_type,
            "certificate": certificate_pem,
        }
        return self._build_call("InstallCertificate", payload)

    def _build_delete_certificate(
        self,
        hash_algorithm: str = "SHA256",
        issuer_name_hash: str = "",
        issuer_key_hash: str = "",
        serial_number: str = "",
    ) -> str:
        """
        Build a DeleteCertificate CALL message (CS -> CP, OCPP 2.0.1).

        Args:
            hash_algorithm: Hash algorithm used ("SHA256", "SHA384", "SHA512")
            issuer_name_hash: Hash of the certificate issuer's distinguished name
            issuer_key_hash: Hash of the certificate issuer's public key
            serial_number: Serial number of the certificate

        Returns:
            JSON-encoded DeleteCertificate CALL message
        """
        payload = {
            "certificateHashData": {
                "hashAlgorithm": hash_algorithm,
                "issuerNameHash": issuer_name_hash,
                "issuerKeyHash": issuer_key_hash,
                "serialNumber": serial_number,
            },
        }
        return self._build_call("DeleteCertificate", payload)

    def _build_get_customer_information(
        self,
        request_id: int = 1,
        report: bool = True,
        clear: bool = False,
        id_token: Optional[str] = None,
        certificate: Optional[str] = None,
    ) -> str:
        """
        Build a CustomerInformation CALL message (CS -> CP, OCPP 2.0.1).

        Args:
            request_id: Unique request ID
            report: Whether to request a report
            clear: Whether to clear customer data
            id_token: Optional ID token value for the customer
            certificate: Optional customer certificate (not used in probe)

        Returns:
            JSON-encoded CustomerInformation CALL message
        """
        payload = {
            "requestId": request_id,
            "report": report,
            "clear": clear,
        }
        if id_token is not None:
            payload["idToken"] = {"idToken": id_token, "type": "ISO14443"}
        if certificate is not None:
            payload["customerCertificate"] = {"certificateType": certificate}
        return self._build_call("CustomerInformation", payload)

    def _build_set_display_message(
        self,
        message_id: int = 1,
        message_text: str = "",
        priority: str = "NormalCycle",
    ) -> str:
        """
        Build a SetDisplayMessage CALL message (CS -> CP, OCPP 2.0.1).

        Args:
            message_id: Unique message ID
            message_text: Message content string
            priority: Display priority ("AlwaysFront", "InFront", "NormalCycle")

        Returns:
            JSON-encoded SetDisplayMessage CALL message
        """
        payload = {
            "message": {
                "id": message_id,
                "priority": priority,
                "message": {
                    "format": "UTF8",
                    "content": message_text,
                },
            },
        }
        return self._build_call("SetDisplayMessage", payload)

    def _build_clear_display_message(self, message_id: int = 1) -> str:
        """
        Build a ClearDisplayMessage CALL message (CS -> CP, OCPP 2.0.1).

        Args:
            message_id: ID of the message to clear

        Returns:
            JSON-encoded ClearDisplayMessage CALL message
        """
        payload = {"id": message_id}
        return self._build_call("ClearDisplayMessage", payload)

    # ==================================================================
    # CP -> CSMS Charging Flow Messages
    # ==================================================================

    def _build_authorize(self, id_tag: str, version: str = "1.6") -> str:
        """
        Build an Authorize CALL message (CP -> CSMS).

        Args:
            id_tag: Authorization ID tag (RFID token)
            version: OCPP version ("1.6" or "2.0.1")

        Returns:
            JSON-encoded Authorize CALL message
        """
        if version.startswith("2."):
            payload = {
                "idToken": {
                    "idToken": id_tag,
                    "type": "ISO14443",
                },
            }
        else:
            payload = {"idTag": id_tag}
        return self._build_call("Authorize", payload)

    def _build_start_transaction(
        self,
        connector_id: int,
        id_tag: str,
        meter_start: int = 0,
        timestamp: Optional[str] = None,
    ) -> str:
        """
        Build a StartTransaction CALL message (CP -> CSMS, OCPP 1.6).

        Args:
            connector_id: Connector where transaction starts
            id_tag: Authorization ID tag
            meter_start: Meter reading at start (Wh)
            timestamp: ISO 8601 timestamp (auto-generated if None)

        Returns:
            JSON-encoded StartTransaction CALL message
        """
        if timestamp is None:
            timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")

        payload = {
            "connectorId": connector_id,
            "idTag": id_tag,
            "meterStart": meter_start,
            "timestamp": timestamp,
        }
        return self._build_call("StartTransaction", payload)

    def _build_stop_transaction(
        self,
        transaction_id: int,
        id_tag: Optional[str] = None,
        meter_stop: int = 0,
        timestamp: Optional[str] = None,
        reason: str = "Local",
    ) -> str:
        """
        Build a StopTransaction CALL message (CP -> CSMS, OCPP 1.6).

        Args:
            transaction_id: Transaction ID from StartTransaction response
            id_tag: Authorization ID tag (optional)
            meter_stop: Meter reading at stop (Wh)
            timestamp: ISO 8601 timestamp (auto-generated if None)
            reason: Stop reason (e.g., "Local", "Remote", "EVDisconnected")

        Returns:
            JSON-encoded StopTransaction CALL message
        """
        if timestamp is None:
            timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")

        payload = {
            "transactionId": transaction_id,
            "meterStop": meter_stop,
            "timestamp": timestamp,
            "reason": reason,
        }
        if id_tag is not None:
            payload["idTag"] = id_tag
        return self._build_call("StopTransaction", payload)

    def _build_transaction_event(
        self,
        event_type: str,
        timestamp: Optional[str] = None,
        trigger_reason: str = "Authorized",
        seq_no: int = 0,
        transaction_info: Optional[Dict[str, Any]] = None,
    ) -> str:
        """
        Build a TransactionEvent CALL message (CP -> CSMS, OCPP 2.0.1).

        Replaces StartTransaction/StopTransaction in OCPP 2.0.1.

        Args:
            event_type: "Started", "Updated", or "Ended"
            timestamp: ISO 8601 timestamp (auto-generated if None)
            trigger_reason: Reason for the event (e.g., "Authorized", "RemoteStart")
            seq_no: Sequence number for this transaction
            transaction_info: Transaction details dict with "transactionId" key

        Returns:
            JSON-encoded TransactionEvent CALL message
        """
        if timestamp is None:
            timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")

        if transaction_info is None:
            transaction_info = {"transactionId": "OIDA-TX-PROBE-001"}

        payload = {
            "eventType": event_type,
            "timestamp": timestamp,
            "triggerReason": trigger_reason,
            "seqNo": seq_no,
            "transactionInfo": transaction_info,
        }
        return self._build_call("TransactionEvent", payload)

    def _build_meter_values(
        self,
        connector_id: int = 1,
        transaction_id: Optional[int] = None,
        meter_value_list: Optional[List[Dict[str, Any]]] = None,
    ) -> str:
        """
        Build a MeterValues CALL message (CP -> CSMS).

        Args:
            connector_id: Connector ID reporting meter values
            transaction_id: Optional transaction ID (OCPP 1.6)
            meter_value_list: List of meterValue objects. Each should contain
                "timestamp" and "sampledValue" list. If None, sends a default
                Energy.Active.Import.Register reading.

        Returns:
            JSON-encoded MeterValues CALL message
        """
        if meter_value_list is None:
            now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
            meter_value_list = [
                {
                    "timestamp": now,
                    "sampledValue": [
                        {
                            "value": "0",
                            "measurand": "Energy.Active.Import.Register",
                            "unit": "Wh",
                        },
                    ],
                },
            ]

        payload = {
            "connectorId": connector_id,
            "meterValue": meter_value_list,
        }
        if transaction_id is not None:
            payload["transactionId"] = transaction_id
        return self._build_call("MeterValues", payload)
