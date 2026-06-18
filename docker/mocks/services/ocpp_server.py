#!/usr/bin/env python3
"""
OCPP Mock CSMS (Central System Management System) Server

Runs two WebSocket server instances:
  - Port 9000: Insecure CSMS (no auth, accepts everything, config exposed)
  - Port 9001: Secure CSMS (HTTP Basic Auth, hardened, rejects unauthorized)

Used for testing the OIDA OCPP scanner end-to-end.

OCPP-J wire format (JSON over WebSocket):
  CALL:       [2, messageId, action, payload]
  CALLRESULT: [3, messageId, payload]
  CALLERROR:  [4, messageId, errorCode, errorDescription, errorDetails]
"""

import asyncio
import base64
import hashlib
import json
import logging
import os
import signal
import sys
from datetime import datetime, timezone
from http import HTTPStatus
from typing import Any, Dict, List, Optional, Tuple

try:
    import websockets
    from websockets.asyncio.server import serve, ServerConnection
    from websockets.http11 import Request, Response

    WS_LEGACY = False
except (ImportError, AttributeError):
    import websockets

    WS_LEGACY = True

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s %(message)s",
    stream=sys.stdout,
)
log = logging.getLogger("ocpp-csms")

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
INSECURE_PORT = int(os.environ.get("OCPP_INSECURE_PORT", "9000"))
SECURE_PORT = int(os.environ.get("OCPP_SECURE_PORT", "9001"))

# Credentials for the secure instance
VALID_USERNAME = os.environ.get("OCPP_USERNAME", "CP001")
VALID_PASSWORD = os.environ.get("OCPP_PASSWORD", "SecureKey123")

OCPP_16_SUBPROTOCOL = "ocpp1.6"
OCPP_201_SUBPROTOCOL = "ocpp2.0.1"
OCPP_21_SUBPROTOCOL = "ocpp2.1"
SUPPORTED_SUBPROTOCOLS = [OCPP_16_SUBPROTOCOL, OCPP_201_SUBPROTOCOL, OCPP_21_SUBPROTOCOL]

# Message types
CALL = 2
CALLRESULT = 3
CALLERROR = 4


def _generate_mock_cert_pem() -> str:
    """Generate a self-signed certificate for the mock CSMS.

    Returns PEM-encoded certificate string.  Uses cryptography if available,
    otherwise falls back to a static PEM blob.
    """
    try:
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        import datetime as _dt

        key = ec.generate_private_key(ec.SECP256R1())
        subject = issuer = x509.Name(
            [
                x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "OIDA Mock CSMS"),
                x509.NameAttribute(NameOID.COMMON_NAME, "ocpp-mock-csms.local"),
            ]
        )
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(_dt.datetime.utcnow())
            .not_valid_after(_dt.datetime.utcnow() + _dt.timedelta(days=365))
            .sign(key, hashes.SHA256())
        )
        return cert.public_bytes(serialization.Encoding.PEM).decode("ascii")
    except ImportError:
        log.debug("cryptography not installed, using static mock cert")
        return ""


# Pre-generate mock certificate at import time
_MOCK_CERT_PEM = _generate_mock_cert_pem()

# ---------------------------------------------------------------------------
# Configuration Key Store (OCPP 1.6)
# ---------------------------------------------------------------------------

CONFIGURATION_KEYS: List[Dict[str, Any]] = [
    {"key": "HeartbeatInterval", "readonly": False, "value": "300"},
    {"key": "ConnectionTimeOut", "readonly": False, "value": "60"},
    {"key": "NumberOfConnectors", "readonly": True, "value": "2"},
    {
        "key": "SupportedFeatureProfiles",
        "readonly": True,
        "value": "Core,FirmwareManagement,SmartCharging,LocalAuthListManagement,Reservation",
    },
    {"key": "MeterValueSampleInterval", "readonly": False, "value": "60"},
    {"key": "MeterValuesAlignedData", "readonly": False, "value": "Energy.Active.Import.Register"},
    {
        "key": "MeterValuesSampledData",
        "readonly": False,
        "value": "Energy.Active.Import.Register,Power.Active.Import,Current.Import,Voltage",
    },
    {"key": "ClockAlignedDataInterval", "readonly": False, "value": "900"},
    {"key": "AuthorizationCacheEnabled", "readonly": False, "value": "true"},
    {"key": "LocalAuthorizeOffline", "readonly": False, "value": "true"},
    {"key": "LocalPreAuthorize", "readonly": False, "value": "false"},
    {"key": "AllowOfflineTxForUnknownId", "readonly": False, "value": "false"},
    {"key": "StopTransactionOnEVSideDisconnect", "readonly": True, "value": "true"},
    {"key": "StopTransactionOnInvalidId", "readonly": True, "value": "true"},
    {"key": "UnlockConnectorOnEVSideDisconnect", "readonly": True, "value": "true"},
    {"key": "WebSocketPingInterval", "readonly": True, "value": "30"},
    {"key": "TransactionMessageAttempts", "readonly": False, "value": "3"},
    {"key": "TransactionMessageRetryInterval", "readonly": False, "value": "60"},
    {"key": "LocalAuthListEnabled", "readonly": False, "value": "true"},
    {"key": "LocalAuthListMaxLength", "readonly": True, "value": "100"},
    {"key": "SendLocalListMaxLength", "readonly": True, "value": "50"},
    {"key": "ReserveConnectorZeroSupported", "readonly": True, "value": "true"},
    {"key": "ChargeProfileMaxStackLevel", "readonly": True, "value": "5"},
    {
        "key": "ChargingScheduleAllowedChargingRateUnit",
        "readonly": True,
        "value": "Current,Power",
    },
    {"key": "ChargingScheduleMaxPeriods", "readonly": True, "value": "24"},
    {"key": "MaxChargingProfilesInstalled", "readonly": True, "value": "10"},
    {"key": "GetConfigurationMaxKeys", "readonly": True, "value": "50"},
    {"key": "AuthorizationKey", "readonly": False, "value": "0000000000000000"},
    {"key": "SecurityProfile", "readonly": False, "value": "0"},
    {"key": "CpoName", "readonly": False, "value": "OIDA-MOCK-CSMS"},
    {"key": "MinimumStatusDuration", "readonly": False, "value": "0"},
    {"key": "ResetRetries", "readonly": True, "value": "3"},
    {"key": "ConnectorPhaseRotation", "readonly": True, "value": "0.RST,1.RST,2.RST"},
    {"key": "LightIntensity", "readonly": False, "value": "100"},
    {"key": "MaxEnergyOnInvalidId", "readonly": False, "value": "0"},
    {"key": "BlinkRepeat", "readonly": False, "value": "3"},
]

# Connector state simulation
CONNECTOR_STATUS = {
    0: "Available",  # Charge point itself
    1: "Available",
    2: "Charging",  # Active session
}

# Track active sessions
_next_transaction_id = 1000


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _next_txn_id() -> int:
    global _next_transaction_id
    tid = _next_transaction_id
    _next_transaction_id += 1
    return tid


# ---------------------------------------------------------------------------
# CSMS Handler
# ---------------------------------------------------------------------------


class CSMSHandler:
    """Handles OCPP messages for a single CP WebSocket connection."""

    def __init__(self, ws: Any, path: str, secure: bool):
        self.ws = ws
        self.path = path
        self.secure = secure
        self.cp_id = path.strip("/").split("/")[-1] if path else "unknown"
        self.mode = "secure" if secure else "insecure"
        self.negotiated = getattr(ws, "subprotocol", None)
        self.is_v201 = self.negotiated in (OCPP_201_SUBPROTOCOL, OCPP_21_SUBPROTOCOL)

        # Deep-copy config so each connection has its own state
        self._config = [dict(k) for k in CONFIGURATION_KEYS]

        # Override security profile for secure instance
        if self.secure:
            for k in self._config:
                if k["key"] == "SecurityProfile":
                    k["value"] = "1"
                    k["readonly"] = True
                elif k["key"] == "AuthorizationKey":
                    k["readonly"] = True

        log.info(
            "[%s] CP %s connected (subproto=%s, path=%s)",
            self.mode,
            self.cp_id,
            self.negotiated,
            self.path,
        )

    async def run(self):
        try:
            async for raw in self.ws:
                try:
                    msg = json.loads(raw)
                except (json.JSONDecodeError, TypeError):
                    log.warning("[%s] Invalid JSON from %s: %r", self.mode, self.cp_id, raw)
                    continue

                if not isinstance(msg, list) or len(msg) < 3:
                    log.warning("[%s] Malformed message from %s: %r", self.mode, self.cp_id, msg)
                    continue

                msg_type = msg[0]
                msg_id = str(msg[1])

                if msg_type == CALL:
                    if len(msg) < 4:
                        await self._send_error(
                            msg_id, "FormationViolation", "CALL must have 4 elements"
                        )
                        continue
                    action = msg[2]
                    payload = msg[3] if len(msg) > 3 else {}
                    await self._handle_call(msg_id, action, payload)

                elif msg_type == CALLRESULT:
                    log.debug(
                        "[%s] CALLRESULT from %s (id=%s): %s",
                        self.mode,
                        self.cp_id,
                        msg_id,
                        msg[2] if len(msg) > 2 else {},
                    )

                elif msg_type == CALLERROR:
                    log.debug(
                        "[%s] CALLERROR from %s (id=%s): %s",
                        self.mode,
                        self.cp_id,
                        msg_id,
                        msg[2:] if len(msg) > 2 else [],
                    )

        except websockets.exceptions.ConnectionClosed:
            log.info("[%s] CP %s disconnected", self.mode, self.cp_id)
        except Exception as e:
            log.error("[%s] Error handling CP %s: %s", self.mode, self.cp_id, e)

    # -------------------------------------------------------------------
    # Message dispatch
    # -------------------------------------------------------------------

    async def _handle_call(self, msg_id: str, action: str, payload: Dict[str, Any]):
        log.info("[%s] CALL from %s: %s", self.mode, self.cp_id, action)

        handler_name = f"_on_{self._snake(action)}"
        handler = getattr(self, handler_name, None)
        if handler:
            try:
                await handler(msg_id, payload)
            except Exception as e:
                log.error("[%s] Handler error for %s: %s", self.mode, action, e)
                await self._send_error(msg_id, "InternalError", str(e))
        else:
            # Unknown action
            if self.secure:
                await self._send_error(msg_id, "NotSupported", f"{action} not supported")
            else:
                await self._send_error(msg_id, "NotImplemented", f"{action} not recognized")

    @staticmethod
    def _snake(name: str) -> str:
        """CamelCase -> snake_case"""
        import re

        s = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1_\2", name)
        s = re.sub(r"([a-z\d])([A-Z])", r"\1_\2", s)
        return s.lower()

    async def _send_result(self, msg_id: str, payload: Dict[str, Any]):
        await self.ws.send(json.dumps([CALLRESULT, msg_id, payload]))

    async def _send_error(
        self, msg_id: str, code: str, desc: str = "", details: Optional[Dict] = None
    ):
        await self.ws.send(json.dumps([CALLERROR, msg_id, code, desc, details or {}]))

    async def _send_call(self, action: str, payload: Dict[str, Any]) -> str:
        """Send a server-initiated CALL to the CP."""
        import uuid

        msg_id = str(uuid.uuid4())[:8]
        await self.ws.send(json.dumps([CALL, msg_id, action, payload]))
        return msg_id

    # -------------------------------------------------------------------
    # CP -> CSMS Actions
    # -------------------------------------------------------------------

    async def _on_boot_notification(self, msg_id: str, payload: Dict[str, Any]):
        if self.secure:
            known_cps = {"CP001", "CP_001", "CP_SCANNER_001"}
            cp_vendor = payload.get("chargePointVendor", "") or payload.get(
                "chargingStation", {}
            ).get("vendorName", "")
            if self.cp_id not in known_cps:
                status = "Pending"
            else:
                status = "Accepted"
        else:
            status = "Accepted"

        await self._send_result(
            msg_id,
            {
                "status": status,
                "interval": 300,
                "currentTime": _now_iso(),
            },
        )

    async def _on_heartbeat(self, msg_id: str, payload: Dict[str, Any]):
        await self._send_result(msg_id, {"currentTime": _now_iso()})

    async def _on_authorize(self, msg_id: str, payload: Dict[str, Any]):
        # OCPP 1.6: idTag, OCPP 2.0.1: idToken.idToken
        id_tag = payload.get("idTag", "")
        if not id_tag:
            token = payload.get("idToken", {})
            id_tag = token.get("idToken", "")

        if self.secure:
            valid_tags = {"VALID_TAG_001", "VALID_TAG_002"}
            status = "Accepted" if id_tag in valid_tags else "Invalid"
        else:
            # Insecure: accept everything
            status = "Accepted"

        if self.is_v201:
            await self._send_result(msg_id, {"idTokenInfo": {"status": status}})
        else:
            await self._send_result(msg_id, {"idTagInfo": {"status": status}})

    async def _on_start_transaction(self, msg_id: str, payload: Dict[str, Any]):
        id_tag = payload.get("idTag", "")
        if self.secure:
            valid_tags = {"VALID_TAG_001", "VALID_TAG_002"}
            status = "Accepted" if id_tag in valid_tags else "Invalid"
        else:
            status = "Accepted"

        await self._send_result(
            msg_id,
            {
                "idTagInfo": {"status": status},
                "transactionId": _next_txn_id(),
            },
        )

    async def _on_stop_transaction(self, msg_id: str, payload: Dict[str, Any]):
        await self._send_result(msg_id, {"idTagInfo": {"status": "Accepted"}})

    async def _on_meter_values(self, msg_id: str, payload: Dict[str, Any]):
        await self._send_result(msg_id, {})

    async def _on_status_notification(self, msg_id: str, payload: Dict[str, Any]):
        await self._send_result(msg_id, {})

    async def _on_data_transfer(self, msg_id: str, payload: Dict[str, Any]):
        vendor_id = payload.get("vendorId", "")
        known_vendors = {"SecurityAudit", "OIDA", "TestVendor"}
        if vendor_id in known_vendors:
            await self._send_result(
                msg_id,
                {
                    "status": "Accepted",
                    "data": json.dumps({"echo": payload.get("data", ""), "ts": _now_iso()}),
                },
            )
        else:
            await self._send_result(msg_id, {"status": "UnknownVendorId"})

    async def _on_diagnostics_status_notification(self, msg_id: str, payload: Dict[str, Any]):
        await self._send_result(msg_id, {})

    async def _on_firmware_status_notification(self, msg_id: str, payload: Dict[str, Any]):
        await self._send_result(msg_id, {})

    async def _on_transaction_event(self, msg_id: str, payload: Dict[str, Any]):
        """OCPP 2.0.1 TransactionEvent"""
        await self._send_result(msg_id, {})

    async def _on_security_event_notification(self, msg_id: str, payload: Dict[str, Any]):
        await self._send_result(msg_id, {})

    async def _on_log_status_notification(self, msg_id: str, payload: Dict[str, Any]):
        await self._send_result(msg_id, {})

    async def _on_notify_report(self, msg_id: str, payload: Dict[str, Any]):
        await self._send_result(msg_id, {})

    async def _on_notify_event(self, msg_id: str, payload: Dict[str, Any]):
        await self._send_result(msg_id, {})

    async def _on_sign_certificate(self, msg_id: str, payload: Dict[str, Any]):
        await self._send_result(msg_id, {"status": "Accepted"})

    # -------------------------------------------------------------------
    # CS -> CP Actions (scanner sends these to test the CSMS)
    # -------------------------------------------------------------------

    async def _on_get_configuration(self, msg_id: str, payload: Dict[str, Any]):
        requested_keys = payload.get("key", [])

        if requested_keys:
            found = []
            unknown = []
            for rk in requested_keys:
                entry = next((c for c in self._config if c["key"] == rk), None)
                if entry:
                    item = {"key": entry["key"], "readonly": entry["readonly"]}
                    # Secure instance hides AuthorizationKey value
                    if self.secure and entry["key"] == "AuthorizationKey":
                        item["value"] = ""
                    else:
                        item["value"] = entry["value"]
                    found.append(item)
                else:
                    unknown.append(rk)
            await self._send_result(msg_id, {"configurationKey": found, "unknownKey": unknown})
        else:
            # Return all keys
            keys = []
            for entry in self._config:
                item = {
                    "key": entry["key"],
                    "readonly": entry["readonly"],
                }
                if self.secure and entry["key"] == "AuthorizationKey":
                    item["value"] = ""
                else:
                    item["value"] = entry["value"]
                keys.append(item)
            await self._send_result(msg_id, {"configurationKey": keys, "unknownKey": []})

    async def _on_change_configuration(self, msg_id: str, payload: Dict[str, Any]):
        key = payload.get("key", "")
        value = payload.get("value", "")

        entry = next((c for c in self._config if c["key"] == key), None)
        if not entry:
            await self._send_result(msg_id, {"status": "NotSupported"})
            return

        if entry["readonly"]:
            await self._send_result(msg_id, {"status": "Rejected"})
            return

        # Secure instance rejects writes to sensitive keys
        sensitive_keys = {"AuthorizationKey", "SecurityProfile", "AllowOfflineTxForUnknownId"}
        if self.secure and key in sensitive_keys:
            await self._send_result(msg_id, {"status": "Rejected"})
            return

        # Secure instance: non-sensitive writable keys require reboot
        if self.secure:
            entry["value"] = value
            await self._send_result(msg_id, {"status": "RebootRequired"})
            return

        # Insecure: allow all writes
        entry["value"] = value
        await self._send_result(msg_id, {"status": "Accepted"})

    async def _on_reset(self, msg_id: str, payload: Dict[str, Any]):
        if self.secure:
            await self._send_result(msg_id, {"status": "Rejected"})
        else:
            await self._send_result(msg_id, {"status": "Accepted"})

    async def _on_remote_start_transaction(self, msg_id: str, payload: Dict[str, Any]):
        if self.secure:
            await self._send_result(msg_id, {"status": "Rejected"})
        else:
            await self._send_result(msg_id, {"status": "Accepted"})

    async def _on_remote_stop_transaction(self, msg_id: str, payload: Dict[str, Any]):
        if self.secure:
            await self._send_result(msg_id, {"status": "Rejected"})
        else:
            await self._send_result(msg_id, {"status": "Accepted"})

    async def _on_unlock_connector(self, msg_id: str, payload: Dict[str, Any]):
        if self.secure:
            await self._send_result(msg_id, {"status": "NotSupported"})
        else:
            await self._send_result(msg_id, {"status": "Unlocked"})

    async def _on_update_firmware(self, msg_id: str, payload: Dict[str, Any]):
        if self.secure:
            await self._send_error(msg_id, "SecurityError", "Firmware update rejected")
        else:
            await self._send_result(msg_id, {})

    async def _on_set_charging_profile(self, msg_id: str, payload: Dict[str, Any]):
        if self.secure:
            await self._send_result(msg_id, {"status": "Rejected"})
        else:
            await self._send_result(msg_id, {"status": "Accepted"})

    async def _on_clear_charging_profile(self, msg_id: str, payload: Dict[str, Any]):
        if self.secure:
            await self._send_result(msg_id, {"status": "Rejected"})
        else:
            await self._send_result(msg_id, {"status": "Accepted"})

    async def _on_trigger_message(self, msg_id: str, payload: Dict[str, Any]):
        requested = payload.get("requestedMessage", "")
        connector_id = payload.get("connectorId", 0)

        # Reject trigger for non-existent connectors (0..NUM_CONNECTORS valid)
        num_connectors = int(
            next((c["value"] for c in self._config if c["key"] == "NumberOfConnectors"), "2")
        )
        if connector_id > num_connectors:
            await self._send_result(msg_id, {"status": "Rejected"})
            return

        # Accept trigger for valid connectors
        await self._send_result(msg_id, {"status": "Accepted"})

        # Then send the requested message asynchronously
        await asyncio.sleep(0.1)

        if requested == "StatusNotification":
            status = CONNECTOR_STATUS.get(connector_id, "Available")
            if self.is_v201:
                await self._send_call(
                    "StatusNotification",
                    {
                        "timestamp": _now_iso(),
                        "connectorStatus": status,
                        "evseId": connector_id,
                        "connectorId": connector_id,
                    },
                )
            else:
                await self._send_call(
                    "StatusNotification",
                    {
                        "connectorId": connector_id,
                        "status": status,
                        "errorCode": "NoError",
                        "timestamp": _now_iso(),
                    },
                )
        elif requested == "MeterValues":
            if self.is_v201:
                await self._send_call(
                    "MeterValues",
                    {
                        "evseId": max(connector_id, 1),
                        "meterValue": [
                            {
                                "timestamp": _now_iso(),
                                "sampledValue": [
                                    {
                                        "value": 15234.5,
                                        "measurand": "Energy.Active.Import.Register",
                                        "unitOfMeasure": {"unit": "Wh"},
                                    }
                                ],
                            }
                        ],
                    },
                )
            else:
                await self._send_call(
                    "MeterValues",
                    {
                        "connectorId": max(connector_id, 1),
                        "meterValue": [
                            {
                                "timestamp": _now_iso(),
                                "sampledValue": [
                                    {
                                        "value": "15234.5",
                                        "measurand": "Energy.Active.Import.Register",
                                        "unit": "Wh",
                                    }
                                ],
                            }
                        ],
                    },
                )
        elif requested == "BootNotification":
            await self._send_call(
                "BootNotification",
                {
                    "chargePointVendor": "OIDA-Mock",
                    "chargePointModel": "MockCSMS-v1",
                    "chargePointSerialNumber": "MOCK-SN-001",
                    "firmwareVersion": "1.0.0",
                },
            )
        elif requested == "Heartbeat":
            await self._send_call("Heartbeat", {})
        elif requested == "FirmwareStatusNotification":
            await self._send_call("FirmwareStatusNotification", {"status": "Idle"})
        elif requested == "DiagnosticsStatusNotification":
            await self._send_call("DiagnosticsStatusNotification", {"status": "Idle"})
        else:
            log.info("[%s] TriggerMessage for unsupported: %s", self.mode, requested)

    async def _on_get_local_list_version(self, msg_id: str, payload: Dict[str, Any]):
        await self._send_result(msg_id, {"listVersion": 1})

    async def _on_send_local_list(self, msg_id: str, payload: Dict[str, Any]):
        if self.secure:
            await self._send_error(msg_id, "NotImplemented", "SendLocalList not supported")
        else:
            await self._send_result(msg_id, {"status": "Accepted"})

    async def _on_get_composite_schedule(self, msg_id: str, payload: Dict[str, Any]):
        connector_id = payload.get("connectorId", 1)
        duration = payload.get("duration", 86400)
        await self._send_result(
            msg_id,
            {
                "status": "Accepted",
                "connectorId": connector_id,
                "scheduleStart": _now_iso(),
                "chargingSchedule": {
                    "duration": duration,
                    "chargingRateUnit": "A",
                    "chargingSchedulePeriod": [
                        {"startPeriod": 0, "limit": 32.0, "numberPhases": 3}
                    ],
                },
            },
        )

    async def _on_cancel_reservation(self, msg_id: str, payload: Dict[str, Any]):
        if self.secure:
            await self._send_result(msg_id, {"status": "Rejected"})
        else:
            await self._send_result(msg_id, {"status": "Accepted"})

    async def _on_reserve_now(self, msg_id: str, payload: Dict[str, Any]):
        if self.secure:
            await self._send_result(msg_id, {"status": "Rejected"})
        else:
            await self._send_result(msg_id, {"status": "Accepted"})

    async def _on_change_availability(self, msg_id: str, payload: Dict[str, Any]):
        if self.secure:
            await self._send_result(msg_id, {"status": "Rejected"})
        else:
            await self._send_result(msg_id, {"status": "Accepted"})

    async def _on_clear_cache(self, msg_id: str, payload: Dict[str, Any]):
        if self.secure:
            await self._send_result(msg_id, {"status": "Rejected"})
        else:
            await self._send_result(msg_id, {"status": "Accepted"})

    async def _on_get_diagnostics(self, msg_id: str, payload: Dict[str, Any]):
        if self.secure:
            await self._send_error(msg_id, "NotImplemented", "GetDiagnostics not supported")
        else:
            await self._send_result(msg_id, {"fileName": "diag-20240101-001.tgz"})

    # -------------------------------------------------------------------
    # OCPP 2.0.1 Actions
    # -------------------------------------------------------------------

    async def _on_get_base_report(self, msg_id: str, payload: Dict[str, Any]):
        request_id = payload.get("requestId", 1)
        await self._send_result(msg_id, {"status": "Accepted"})

        # Send NotifyReport with EVSE/Connector topology data
        await asyncio.sleep(0.1)
        num_connectors = int(
            next((c["value"] for c in self._config if c["key"] == "NumberOfConnectors"), "2")
        )
        report_data = []
        for evse_id in range(1, num_connectors + 1):
            status = CONNECTOR_STATUS.get(evse_id, "Available")
            report_data.append(
                {
                    "component": {"name": "EVSE", "evse": {"id": evse_id}},
                    "variable": {"name": "AvailabilityState"},
                    "variableAttribute": [{"value": status}],
                    "variableCharacteristics": {"dataType": "string"},
                }
            )
            report_data.append(
                {
                    "component": {
                        "name": "Connector",
                        "evse": {"id": evse_id, "connectorId": 1},
                    },
                    "variable": {"name": "AvailabilityState"},
                    "variableAttribute": [{"value": status}],
                    "variableCharacteristics": {"dataType": "string"},
                }
            )
        await self._send_call(
            "NotifyReport",
            {
                "requestId": request_id,
                "generatedAt": _now_iso(),
                "tbc": False,
                "seqNo": 0,
                "reportData": report_data,
            },
        )

    async def _on_get_variables(self, msg_id: str, payload: Dict[str, Any]):
        requested = payload.get("getVariableData", [])
        results = []
        if requested and any(r.get("variable", {}).get("name") for r in requested):
            # Specific variables requested
            for var_req in requested:
                comp = var_req.get("component", {}).get("name", "")
                var_name = var_req.get("variable", {}).get("name", "")
                entry = next((c for c in self._config if c["key"] == var_name), None)
                if entry:
                    value = entry["value"]
                    if self.secure and entry["key"] == "AuthorizationKey":
                        value = ""
                    results.append(
                        {
                            "attributeStatus": "Accepted",
                            "component": {"name": comp or "OCPPCommCtrlr"},
                            "variable": {"name": var_name},
                            "attributeValue": value,
                        }
                    )
                else:
                    results.append(
                        {
                            "attributeStatus": "UnknownVariable",
                            "component": {"name": comp or "OCPPCommCtrlr"},
                            "variable": {"name": var_name},
                        }
                    )
        else:
            # Return all variables
            for entry in self._config:
                value = entry["value"]
                if self.secure and entry["key"] == "AuthorizationKey":
                    value = ""
                results.append(
                    {
                        "attributeStatus": "Accepted",
                        "component": {"name": "OCPPCommCtrlr"},
                        "variable": {"name": entry["key"]},
                        "attributeValue": value,
                    }
                )
        await self._send_result(msg_id, {"getVariableResult": results})

    async def _on_set_variables(self, msg_id: str, payload: Dict[str, Any]):
        results = []
        for var_req in payload.get("setVariableData", []):
            comp = var_req.get("component", {}).get("name", "")
            var_name = var_req.get("variable", {}).get("name", "")
            new_value = var_req.get("attributeValue", "")
            entry = next((c for c in self._config if c["key"] == var_name), None)
            if self.secure:
                # Secure instance: reject sensitive keys, accept only non-readonly
                if entry and entry["readonly"]:
                    status = "Rejected"
                elif var_name in ("AuthorizationKey", "SecurityProfile"):
                    status = "Rejected"
                else:
                    status = "Rejected"
            else:
                # Insecure instance: accept everything
                status = "Accepted"
                if entry:
                    entry["value"] = new_value
            results.append(
                {
                    "attributeStatus": status,
                    "component": {"name": comp or "OCPPCommCtrlr"},
                    "variable": {"name": var_name},
                }
            )
        await self._send_result(msg_id, {"setVariableResult": results})

    async def _on_get_log(self, msg_id: str, payload: Dict[str, Any]):
        if self.secure:
            await self._send_error(msg_id, "NotImplemented", "GetLog not supported")
        else:
            await self._send_result(msg_id, {"status": "Accepted", "filename": "log-001.tgz"})

    async def _on_get_installed_certificate_ids(self, msg_id: str, payload: Dict[str, Any]):
        # Build hash data from real cert if available
        cert_hash_data = {
            "hashAlgorithm": "SHA256",
            "issuerNameHash": "AABB" * 8,
            "issuerKeyHash": "CCDD" * 8,
            "serialNumber": "0001",
        }
        if _MOCK_CERT_PEM:
            # Compute real hashes from the generated certificate
            der_lines = []
            in_cert = False
            for line in _MOCK_CERT_PEM.splitlines():
                if "BEGIN CERTIFICATE" in line:
                    in_cert = True
                    continue
                if "END CERTIFICATE" in line:
                    break
                if in_cert:
                    der_lines.append(line)
            der_bytes = base64.b64decode("".join(der_lines))
            cert_hash_data["issuerNameHash"] = hashlib.sha256(der_bytes[:128]).hexdigest()[:32]
            cert_hash_data["issuerKeyHash"] = hashlib.sha256(der_bytes[-128:]).hexdigest()[:32]

        chain_entry = {
            "certificateType": "CSMSRootCertificate",
            "certificateHashData": cert_hash_data,
        }
        # Include PEM so scanners can parse the actual certificate
        if _MOCK_CERT_PEM:
            chain_entry["certificate"] = _MOCK_CERT_PEM

        await self._send_result(
            msg_id,
            {
                "status": "Accepted",
                "certificateHashDataChain": [chain_entry],
            },
        )

    async def _on_get_report(self, msg_id: str, payload: Dict[str, Any]):
        await self._send_result(msg_id, {"status": "Accepted"})

    async def _on_get_monitoring_report(self, msg_id: str, payload: Dict[str, Any]):
        await self._send_result(msg_id, {"status": "Accepted"})

    async def _on_get_transaction_status(self, msg_id: str, payload: Dict[str, Any]):
        await self._send_result(msg_id, {"ongoingIndicator": False, "messagesInQueue": False})

    async def _on_request_start_transaction(self, msg_id: str, payload: Dict[str, Any]):
        if self.secure:
            await self._send_result(msg_id, {"status": "Rejected"})
        else:
            await self._send_result(
                msg_id, {"status": "Accepted", "transactionId": str(_next_txn_id())}
            )

    async def _on_request_stop_transaction(self, msg_id: str, payload: Dict[str, Any]):
        if self.secure:
            await self._send_result(msg_id, {"status": "Rejected"})
        else:
            await self._send_result(msg_id, {"status": "Accepted"})

    async def _on_cost_updated(self, msg_id: str, payload: Dict[str, Any]):
        await self._send_result(msg_id, {})

    async def _on_customer_information(self, msg_id: str, payload: Dict[str, Any]):
        await self._send_result(msg_id, {"status": "Accepted"})

    async def _on_get_display_messages(self, msg_id: str, payload: Dict[str, Any]):
        await self._send_result(msg_id, {"status": "Accepted"})

    async def _on_get_charging_profiles(self, msg_id: str, payload: Dict[str, Any]):
        await self._send_result(msg_id, {"status": "Accepted"})

    async def _on_install_certificate(self, msg_id: str, payload: Dict[str, Any]):
        if self.secure:
            await self._send_result(msg_id, {"status": "Rejected"})
        else:
            await self._send_result(msg_id, {"status": "Accepted"})

    async def _on_delete_certificate(self, msg_id: str, payload: Dict[str, Any]):
        if self.secure:
            await self._send_result(msg_id, {"status": "Rejected"})
        else:
            await self._send_result(msg_id, {"status": "Accepted"})

    async def _on_certificate_signed(self, msg_id: str, payload: Dict[str, Any]):
        await self._send_result(msg_id, {"status": "Accepted"})

    async def _on_publish_firmware(self, msg_id: str, payload: Dict[str, Any]):
        if self.secure:
            await self._send_error(msg_id, "SecurityError", "Firmware update rejected")
        else:
            await self._send_result(msg_id, {"status": "Accepted"})

    async def _on_unpublish_firmware(self, msg_id: str, payload: Dict[str, Any]):
        await self._send_result(msg_id, {"status": "Accepted"})

    async def _on_set_network_profile(self, msg_id: str, payload: Dict[str, Any]):
        if self.secure:
            await self._send_result(msg_id, {"status": "Rejected"})
        else:
            await self._send_result(msg_id, {"status": "Accepted"})

    async def _on_set_display_message(self, msg_id: str, payload: Dict[str, Any]):
        await self._send_result(msg_id, {"status": "Accepted"})

    async def _on_clear_display_message(self, msg_id: str, payload: Dict[str, Any]):
        await self._send_result(msg_id, {"status": "Accepted"})

    async def _on_set_monitoring_base(self, msg_id: str, payload: Dict[str, Any]):
        await self._send_result(msg_id, {"status": "Accepted"})

    async def _on_set_monitoring_level(self, msg_id: str, payload: Dict[str, Any]):
        await self._send_result(msg_id, {"status": "Accepted"})

    async def _on_set_variable_monitoring(self, msg_id: str, payload: Dict[str, Any]):
        await self._send_result(msg_id, {"setMonitoringResult": []})

    async def _on_clear_variable_monitoring(self, msg_id: str, payload: Dict[str, Any]):
        await self._send_result(msg_id, {"clearMonitoringResult": []})


# ---------------------------------------------------------------------------
# Server Setup
# ---------------------------------------------------------------------------


def _check_basic_auth(headers: Any) -> Optional[Tuple[str, str]]:
    """Extract and validate HTTP Basic Auth from request headers."""
    auth_header = None
    if isinstance(headers, dict):
        auth_header = headers.get("Authorization") or headers.get("authorization")
    else:
        # websockets Headers object
        auth_header = getattr(headers, "get", lambda k, d=None: d)("Authorization")
        if not auth_header:
            auth_header = getattr(headers, "get", lambda k, d=None: d)("authorization")
    if not auth_header:
        return None

    if not auth_header.startswith("Basic "):
        return None

    try:
        decoded = base64.b64decode(auth_header[6:]).decode("utf-8")
        if ":" in decoded:
            user, passwd = decoded.split(":", 1)
            return (user, passwd)
    except Exception:
        pass
    return None


async def _insecure_handler(ws: Any, path: str = ""):
    """Handler for insecure (port 9000) connections."""
    handler = CSMSHandler(ws, path, secure=False)
    await handler.run()


async def _secure_handler(ws: Any, path: str = ""):
    """Handler for secure (port 9001) connections with auth enforcement."""
    handler = CSMSHandler(ws, path, secure=True)
    await handler.run()


def _select_subprotocol(client_protocols: Any, server_protocols: Any) -> Optional[str]:
    """Select best subprotocol match."""
    if isinstance(client_protocols, str):
        client_protocols = [client_protocols]
    client_list = list(client_protocols) if client_protocols else []
    for proto in client_list:
        if proto in SUPPORTED_SUBPROTOCOLS:
            return proto
    return None


async def run_servers():
    """Start both insecure and secure WebSocket servers."""
    log.info("Starting OCPP Mock CSMS...")
    log.info("  Insecure: ws://0.0.0.0:%d/<CP_ID>  (no auth, accepts all)", INSECURE_PORT)
    log.info(
        "  Secure:   ws://0.0.0.0:%d/<CP_ID>  (Basic Auth: %s:%s)",
        SECURE_PORT,
        VALID_USERNAME,
        VALID_PASSWORD,
    )

    if WS_LEGACY:
        # websockets < 14.x (legacy serve API)
        log.info("Using websockets legacy API")

        async def insecure_legacy(ws, path):
            await _insecure_handler(ws, path)

        async def secure_process_request(path, request_headers):
            """Enforce Basic Auth on the secure instance."""
            creds = _check_basic_auth(request_headers)
            if creds is None:
                return (
                    HTTPStatus.UNAUTHORIZED,
                    [("WWW-Authenticate", 'Basic realm="OCPP CSMS"')],
                    b"401 Unauthorized\n",
                )
            user, passwd = creds
            if user != VALID_USERNAME or passwd != VALID_PASSWORD:
                return (
                    HTTPStatus.FORBIDDEN,
                    [],
                    b"403 Forbidden: Invalid credentials\n",
                )
            return None

        async def secure_legacy(ws, path):
            await _secure_handler(ws, path)

        insecure_server = await websockets.serve(
            insecure_legacy,
            "0.0.0.0",
            INSECURE_PORT,
            subprotocols=SUPPORTED_SUBPROTOCOLS,
            ping_interval=30,
            ping_timeout=10,
        )

        secure_server = await websockets.serve(
            secure_legacy,
            "0.0.0.0",
            SECURE_PORT,
            subprotocols=SUPPORTED_SUBPROTOCOLS,
            process_request=secure_process_request,
            ping_interval=30,
            ping_timeout=10,
        )
    else:
        # websockets >= 14.x (new asyncio serve API)
        log.info("Using websockets modern API (>=14.x)")

        def insecure_process_request(
            connection: ServerConnection, request: Request
        ) -> Optional[Response]:
            return None

        def secure_process_request(
            connection: ServerConnection, request: Request
        ) -> Optional[Response]:
            # Enforce Basic Auth
            creds = _check_basic_auth(request.headers)
            if creds is None:
                return Response(
                    401,
                    "Unauthorized",
                    websockets.Headers(
                        [
                            ("WWW-Authenticate", 'Basic realm="OCPP CSMS"'),
                            ("Content-Type", "text/plain"),
                        ]
                    ),
                    b"401 Unauthorized\n",
                )
            user, passwd = creds
            if user != VALID_USERNAME or passwd != VALID_PASSWORD:
                return Response(
                    403,
                    "Forbidden",
                    websockets.Headers([("Content-Type", "text/plain")]),
                    b"403 Forbidden: Invalid credentials\n",
                )
            return None

        def _pick_subprotocol(connection, subprotocols):
            """Select the best OCPP subprotocol from client's list."""
            for proto in subprotocols:
                if proto in SUPPORTED_SUBPROTOCOLS:
                    return proto
            return None

        async def insecure_modern(ws: ServerConnection):
            path = getattr(ws, "request", None)
            path_str = path.path if path else ""
            await _insecure_handler(ws, path_str)

        async def secure_modern(ws: ServerConnection):
            path = getattr(ws, "request", None)
            path_str = path.path if path else ""
            await _secure_handler(ws, path_str)

        insecure_server = await serve(
            insecure_modern,
            "0.0.0.0",
            INSECURE_PORT,
            subprotocols=SUPPORTED_SUBPROTOCOLS,
            select_subprotocol=_pick_subprotocol,
            process_request=insecure_process_request,
            ping_interval=30,
            ping_timeout=10,
        )

        secure_server = await serve(
            secure_modern,
            "0.0.0.0",
            SECURE_PORT,
            subprotocols=SUPPORTED_SUBPROTOCOLS,
            select_subprotocol=_pick_subprotocol,
            process_request=secure_process_request,
            ping_interval=30,
            ping_timeout=10,
        )

    log.info("OCPP Mock CSMS running. Ctrl+C to stop.")
    stop = asyncio.Event()
    loop = asyncio.get_event_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, stop.set)
    await stop.wait()

    insecure_server.close()
    secure_server.close()
    await insecure_server.wait_closed()
    await secure_server.wait_closed()
    log.info("OCPP Mock CSMS stopped.")


if __name__ == "__main__":
    asyncio.run(run_servers())
