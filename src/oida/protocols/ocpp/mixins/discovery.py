"""
OCPP Discovery Mixin

Provides version detection, endpoint enumeration, configuration
enumeration, and WebSocket path brute-forcing for the NXC-style
OCPP connection class.
"""

import time
from typing import Any, Dict, List, Optional

from ....utils.lazy_import import lazy_import
from ....utils.platform_compat import _pkg_root
from ..constants import (
    MessageType,
    SUBPROTOCOL_TO_VERSION,
    ALL_ACTIONS_V16,
    ALL_ACTIONS_V201,
)

_security_findings = lazy_import(
    "oida.utils.security_findings",
    "ocpp",
    install_hint="pip install cryptography",
)


class DiscoveryMixin:
    """Mixin for OCPP version detection and endpoint enumeration"""

    def _handle_version_detection(self):
        """
        Detect OCPP version from the negotiated WebSocket subprotocol.

        Reads the subprotocol from the active connection and stores
        the detected version in results.
        """
        if not self.conn:
            return

        detected_version = None

        # The WebSocket subprotocol is set during the handshake
        subprotocol = getattr(self.conn, "subprotocol", None)
        if subprotocol:
            detected_version = SUBPROTOCOL_TO_VERSION.get(subprotocol, subprotocol)
            self.logger.debug(f"Version negotiated: {detected_version} (subprotocol={subprotocol})")
            self.logger.display(
                f"    OCPP Version: {detected_version} (subprotocol: {subprotocol})"
            )
        else:
            self.logger.debug("No subprotocol negotiated, version unknown")
            self.logger.display("    OCPP Version: Unknown (no subprotocol negotiated)")

        self.results["data"]["ocpp_version"] = detected_version
        self.results["data"]["subprotocol"] = subprotocol

    def _handle_boot_notification(self):
        """
        Send a BootNotification and analyze the response.

        This is a safe, read-only operation that identifies how the CSMS
        responds to a new charge point connection.
        """
        if not self.conn:
            return

        version = self.results["data"].get("ocpp_version", "1.6")
        self.logger.debug(f"Sending BootNotification (version={version or '1.6'})")
        boot_msg = self._build_boot_notification(version or "1.6")

        try:
            response = self.scanner._send_and_receive(self.conn, boot_msg)
            if response is None:
                self.logger.warning("No response to BootNotification")
                self.results["data"]["boot_notification"] = {"status": "no_response"}
                return

            msg_type, _, payload = self._parse_message(response)

            if msg_type == MessageType.CALLRESULT:
                status = payload.get("status", "Unknown")
                interval = payload.get("interval", 0)
                current_time = payload.get("currentTime", "")

                self.logger.debug(
                    f"BootNotification response: status={status}, interval={interval}s"
                )
                self.logger.display(f"    BootNotification: {status}")
                if current_time:
                    self.logger.display(f"    Server Time: {current_time}")
                if interval:
                    self.logger.display(f"    Heartbeat Interval: {interval}s")

                self.results["data"]["boot_notification"] = {
                    "status": status,
                    "interval": interval,
                    "current_time": current_time,
                }

            elif msg_type == MessageType.CALLERROR:
                error_code = payload.get("error_code", "Unknown")
                error_desc = payload.get("error_description", "")
                self.logger.debug(f"BootNotification CALLERROR: {error_code} - {error_desc}")
                self.logger.warning(f"BootNotification error: {error_code} - {error_desc}")
                self.results["data"]["boot_notification"] = {
                    "status": "error",
                    "error_code": error_code,
                    "error_description": error_desc,
                }

        except Exception as e:
            self.logger.debug(f"BootNotification failed: {e}")
            self.results["data"]["boot_notification"] = {"status": "error", "error": str(e)}

    def _handle_heartbeat(self):
        """
        Send a Heartbeat message and check response.

        Used to verify connectivity and get server time.
        """
        if not self.conn:
            return

        self.logger.debug("Sending Heartbeat")
        heartbeat_msg = self._build_heartbeat()

        try:
            response = self.scanner._send_and_receive(self.conn, heartbeat_msg)
            if response is None:
                self.logger.debug("Heartbeat: no response")
                return

            msg_type, _, payload = self._parse_message(response)

            if msg_type == MessageType.CALLRESULT:
                current_time = payload.get("currentTime", "")
                if current_time:
                    self.logger.debug(f"Heartbeat response: server_time={current_time}")
                    self.logger.display(f"    Heartbeat Response: {current_time}")
                    self.results["data"]["heartbeat"] = {"current_time": current_time}

        except Exception as e:
            self.logger.debug(f"Heartbeat failed: {e}")

    # Actions that may have side-effects when probed with empty payloads
    _DANGEROUS_ACTIONS = {
        "Reset",
        "UpdateFirmware",
        "ChangeConfiguration",
        "RemoteStartTransaction",
        "RemoteStopTransaction",
        "SetChargingProfile",
        "UnlockConnector",
        "ClearCache",
        "SendLocalList",
        "ChangeAvailability",
        "GetDiagnostics",
    }

    def _handle_enumerate_actions(self):
        """
        Enumerate supported OCPP actions by sending probe messages.

        Sends each known action with a minimal payload and checks whether
        the response is NotImplemented, NotSupported, or something else.

        Dangerous actions (Reset, Unlock, etc.) are skipped unless --confirm
        is set, since some servers may execute them even with empty payloads.
        """
        if not self.conn:
            return

        version = self.results["data"].get("ocpp_version", "1.6")
        confirmed = getattr(self.args, "confirm", False)

        if version and version.startswith("2."):
            all_actions = list(ALL_ACTIONS_V201)
            self.logger.debug(f"Using OCPP 2.0.1 action set ({len(all_actions)} actions)")
        else:
            all_actions = list(ALL_ACTIONS_V16)
            self.logger.debug(f"Using OCPP 1.6 action set ({len(all_actions)} actions)")

        # Split safe vs dangerous
        skipped = [a for a in all_actions if a in self._DANGEROUS_ACTIONS] if not confirmed else []
        actions_to_test = (
            all_actions
            if confirmed
            else [a for a in all_actions if a not in self._DANGEROUS_ACTIONS]
        )

        if skipped:
            self.logger.display(
                f"[Action Enumeration] Testing {len(actions_to_test)} actions "
                f"(skipping {len(skipped)} dangerous, use --confirm to include)"
            )
        else:
            self.logger.display(f"[Action Enumeration] Testing {len(actions_to_test)} actions...")

        supported = []
        not_supported = []
        not_implemented = []
        errors = []

        for action in actions_to_test:
            try:
                probe_msg = self._build_call(action, {})
                response = self.scanner._send_and_receive(self.conn, probe_msg, timeout=3)

                if response is None:
                    errors.append(action)
                    continue

                msg_type, _, payload = self._parse_message(response)

                if msg_type == MessageType.CALLRESULT:
                    supported.append(action)
                elif msg_type == MessageType.CALLERROR:
                    error_code = payload.get("error_code", "")
                    if error_code == "NotImplemented":
                        not_implemented.append(action)
                    elif error_code == "NotSupported":
                        not_supported.append(action)
                    else:
                        # Other errors (FormationViolation, etc.) mean the action
                        # is recognized but our payload was invalid - so it's supported
                        supported.append(action)

            except Exception as e:
                self.logger.debug(f"Action probe {action} failed: {e}")
                errors.append(action)

        # Display results
        if supported:
            exposed_dangerous = [a for a in supported if a in self._DANGEROUS_ACTIONS]
            safe_actions = [a for a in supported if a not in self._DANGEROUS_ACTIONS]

            self.logger.display(f"  Supported actions ({len(supported)}):")
            for action in safe_actions:
                self.logger.display(f"    {action}")
            for action in exposed_dangerous:
                self.logger.warning(f"    {action} (dangerous)")

            if exposed_dangerous:
                self._add_finding(
                    "HIGH",
                    f"Dangerous OCPP actions accessible ({len(exposed_dangerous)})",
                    f"Actions: {', '.join(exposed_dangerous)}",
                )

        if not_supported:
            self.logger.display(f"  Not supported ({len(not_supported)}):")
            for action in not_supported:
                self.logger.display(f"    {action}")

        if not_implemented:
            self.logger.display(f"  Not implemented ({len(not_implemented)}):")
            for action in not_implemented:
                self.logger.display(f"    {action}")

        if skipped:
            self.logger.display(f"  Skipped ({len(skipped)}, add --confirm to probe):")
            for action in skipped:
                self.logger.display(f"    {action}")

        self.logger.debug(
            f"Action enumeration complete: {len(supported)} supported, "
            f"{len(not_supported)} not_supported, {len(not_implemented)} not_implemented, "
            f"{len(errors)} errors, {len(skipped)} skipped"
        )
        self.results["data"]["actions"] = {
            "supported": supported,
            "not_supported": not_supported,
            "not_implemented": not_implemented,
            "errors": errors,
            "skipped": skipped,
        }

    def _handle_get_configuration(self):
        """
        Attempt to retrieve configuration from the charge point (OCPP 1.6).

        Sends a GetConfiguration request. This is typically a CS->CP action,
        so it may be rejected if we are acting as a charge point. However,
        some misconfigured systems respond to it regardless of role.
        """
        if not self.conn:
            return

        version = self.results["data"].get("ocpp_version", "1.6") or "1.6"
        self.logger.debug("Sending GetConfiguration (all keys)")
        self.logger.display("[Configuration Enumeration]")

        # Try requesting all configuration keys
        get_config_msg = self._build_get_configuration(version=version)

        try:
            response = self.scanner._send_and_receive(self.conn, get_config_msg, timeout=5)
            if response is None:
                self.logger.display("  No response to GetConfiguration (expected for CP role)")
                return

            msg_type, _, payload = self._parse_message(response)

            if msg_type == MessageType.CALLRESULT:
                if version.startswith("2."):
                    # OCPP 2.0.1: GetVariables response
                    var_results = payload.get("getVariableResult", [])
                    config_keys = []
                    unknown_keys = []
                    for r in var_results:
                        attr_status = r.get("attributeStatus", "")
                        var_name = r.get("variable", {}).get("name", "?")
                        if attr_status == "Accepted":
                            config_keys.append(
                                {
                                    "key": var_name,
                                    "value": r.get("attributeValue", ""),
                                    "readonly": False,
                                }
                            )
                        elif attr_status in ("UnknownVariable", "UnknownComponent"):
                            unknown_keys.append(var_name)
                        else:
                            config_keys.append(
                                {
                                    "key": var_name,
                                    "value": r.get("attributeValue", ""),
                                    "readonly": attr_status == "Rejected",
                                }
                            )
                else:
                    config_keys = payload.get("configurationKey", [])
                    unknown_keys = payload.get("unknownKey", [])

                self.logger.debug(
                    f"GetConfiguration response: {len(config_keys)} keys, "
                    f"{len(unknown_keys)} unknown"
                )

                if config_keys:
                    self.logger.display(f"  Configuration keys ({len(config_keys)}):")
                    for key_info in config_keys:
                        key = key_info.get("key", "?")
                        value = key_info.get("value", "")
                        readonly = key_info.get("readonly", False)
                        ro_tag = " [RO]" if readonly else " [RW]"
                        self.logger.display(f"    {key}: {value}{ro_tag}")

                if unknown_keys:
                    self.logger.display(f"  Unknown keys: {', '.join(unknown_keys)}")

                self.results["data"]["configuration"] = {
                    "keys": config_keys,
                    "unknown_keys": unknown_keys,
                }

            elif msg_type == MessageType.CALLERROR:
                error_code = payload.get("error_code", "")
                self.logger.display(f"  GetConfiguration: {error_code} (normal for CP role)")

        except Exception as e:
            self.logger.debug(f"GetConfiguration failed: {e}")

    def _handle_data_transfer_probe(self):
        """
        Send a DataTransfer message to probe for vendor extensions.

        DataTransfer is used for vendor-specific functionality and can
        reveal information about the implementation.
        """
        if not self.conn:
            return

        self.logger.debug("Sending DataTransfer probe (vendorId=SecurityAudit)")
        dt_msg = self._build_data_transfer(
            vendor_id="SecurityAudit",
            message_id="probe",
            data="ping",
        )

        try:
            response = self.scanner._send_and_receive(self.conn, dt_msg, timeout=3)
            if response is None:
                return

            msg_type, _, payload = self._parse_message(response)

            if msg_type == MessageType.CALLRESULT:
                status = payload.get("status", "Unknown")
                data = payload.get("data", "")
                self.logger.debug(f"DataTransfer response: status={status}")
                self.logger.display(f"    DataTransfer: {status}")
                if data:
                    self.logger.display(f"    DataTransfer data: {data}")
                self.results["data"]["data_transfer"] = {"status": status, "data": data}

            elif msg_type == MessageType.CALLERROR:
                error_code = payload.get("error_code", "")
                self.logger.debug(f"DataTransfer error: {error_code}")

        except Exception as e:
            self.logger.debug(f"DataTransfer probe failed: {e}")

    # Config keys that commonly expose firmware / version details.
    _FIRMWARE_CONFIG_KEYS = [
        "FirmwareVersion",
        "ChargePointModel",
        "ChargePointVendor",
        "ChargeBoxSerialNumber",
        "MeterSerialNumber",
        "MeterType",
    ]

    def _handle_firmware_info(self):
        """
        Gather firmware / hardware details from the charge point.

        Combines the BootNotification result (already captured during connect)
        with a targeted GetConfiguration request for firmware-related keys.
        Read-only.
        """
        if not self.conn:
            return

        version = self.results["data"].get("ocpp_version", "1.6") or "1.6"
        self.logger.display("[Firmware / Hardware Info]")

        info = {}
        boot = self.results["data"].get("boot_notification", {})
        if boot:
            info["boot_status"] = boot.get("status")

        get_config_msg = self._build_get_configuration(
            keys=self._FIRMWARE_CONFIG_KEYS, version=version
        )

        try:
            response = self.scanner._send_and_receive(self.conn, get_config_msg, timeout=5)
            if response is not None:
                msg_type, _, payload = self._parse_message(response)
                if msg_type == MessageType.CALLRESULT:
                    if version.startswith("2."):
                        results = payload.get("getVariableResult", [])
                        for r in results:
                            name = r.get("variable", {}).get("name", "")
                            value = r.get("attributeValue", "")
                            if name and value:
                                info[name] = value
                    else:
                        for key_info in payload.get("configurationKey", []):
                            key = key_info.get("key", "")
                            value = key_info.get("value", "")
                            if key and value:
                                info[key] = value
                elif msg_type == MessageType.CALLERROR:
                    error_code = payload.get("error_code", "")
                    self.logger.debug(f"Firmware GetConfiguration: {error_code}")
        except Exception as e:
            self.logger.debug(f"Firmware info gathering failed: {e}")

        for key, value in info.items():
            self.logger.display(f"    {key}: {value}")
        if not info:
            self.logger.display("    No firmware details exposed")

        self.results["data"]["firmware_info"] = info

    def probe_meter_values(self):
        """
        Probe MeterValues by sending a TriggerMessage requesting MeterValues.

        Parses the response to extract energy, power, current, and voltage
        data for asset inventory purposes. This is a read-only operation.
        """
        if not self.conn:
            return

        self.logger.display("[MeterValues Probe]")

        connector_id = getattr(self.args, "connector_id", 0) or 0
        self.logger.debug(f"Sending TriggerMessage(MeterValues) for connector {connector_id}")
        trigger_msg = self._build_trigger_message("MeterValues", connector_id)

        try:
            response = self.scanner._send_and_receive(self.conn, trigger_msg, timeout=5)
            if response is None:
                self.logger.display("  No response to MeterValues trigger")
                self.results["data"]["meter_values"] = {"status": "no_response"}
                return

            msg_type, _, payload = self._parse_message(response)

            if msg_type == MessageType.CALLRESULT:
                # TriggerMessage response is just {"status": "Accepted"/"Rejected"/"NotImplemented"}
                status = payload.get("status", "Unknown")
                self.logger.display(f"  TriggerMessage(MeterValues): {status}")

                meter_data = {"trigger_status": status, "values": []}

                if status == "Accepted":
                    # The charge point should now asynchronously send MeterValues
                    # Try to receive the follow-up MeterValues CALL from the CP
                    self.logger.debug("MeterValues trigger accepted, waiting for async values")
                    meter_data["values"] = self._receive_meter_values()

                self.results["data"]["meter_values"] = meter_data

            elif msg_type == MessageType.CALLERROR:
                error_code = payload.get("error_code", "")
                self.logger.display(f"  MeterValues trigger: {error_code}")
                self.results["data"]["meter_values"] = {
                    "trigger_status": "error",
                    "error_code": error_code,
                    "values": [],
                }

            # Also check if CALL came back (CP sending MeterValues to us as CSMS)
            elif msg_type == MessageType.CALL:
                action = payload.get("action", "")
                if action == "MeterValues":
                    meter_payload = payload.get("payload", {})
                    values = self._extract_meter_values(meter_payload)
                    self.results["data"]["meter_values"] = {
                        "trigger_status": "direct_response",
                        "values": values,
                    }
                    self._display_meter_values(values)

        except Exception as e:
            self.logger.debug(f"MeterValues probe failed: {e}")
            self.results["data"]["meter_values"] = {
                "trigger_status": "error",
                "error": str(e),
                "values": [],
            }

    def _receive_meter_values(self) -> List[Dict[str, Any]]:
        """
        Try to receive an asynchronous MeterValues CALL message from the charge point.

        Returns:
            List of parsed meter value dictionaries
        """
        try:
            loop = getattr(self.scanner, "_event_loop", None)
            if not loop or loop.is_closed():
                return []

            import asyncio

            async def _recv():
                try:
                    return await asyncio.wait_for(self.conn.recv(), timeout=3)
                except asyncio.TimeoutError:
                    self.logger.debug("No async MeterValues received within timeout")
                    return None

            raw = loop.run_until_complete(_recv())
            if raw is None:
                return []

            msg_type, msg_id, payload = self._parse_message(raw)

            if msg_type == MessageType.CALL:
                action = payload.get("action", "")
                if action == "MeterValues":
                    meter_payload = payload.get("payload", {})
                    values = self._extract_meter_values(meter_payload)
                    self._display_meter_values(values)

                    # Send CALLRESULT acknowledgement
                    ack = self._build_call_result(msg_id, {})
                    self.scanner._send_and_receive(self.conn, ack, timeout=1)

                    return values

        except Exception as e:
            self.logger.debug(f"MeterValues receive failed: {e}")

        return []

    def _extract_meter_values(self, payload: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Extract measurand data from a MeterValues payload.

        Args:
            payload: MeterValues CALL payload

        Returns:
            List of {measurand, value, unit, phase} dictionaries
        """
        values = []
        meter_value_list = payload.get("meterValue", [])

        for mv in meter_value_list:
            sampled_values = mv.get("sampledValue", [])
            for sv in sampled_values:
                entry = {
                    "measurand": sv.get("measurand", "Energy.Active.Import.Register"),
                    "value": sv.get("value", "0"),
                    "unit": sv.get("unit", ""),
                    "phase": sv.get("phase", ""),
                    "context": sv.get("context", ""),
                    "format": sv.get("format", "Raw"),
                    "location": sv.get("location", ""),
                }
                values.append(entry)

        return values

    def _display_meter_values(self, values: List[Dict[str, Any]]):
        """Display parsed meter values."""
        if not values:
            self.logger.display("  No meter values received")
            return

        self.logger.display(f"  Meter values ({len(values)} readings):")
        for v in values:
            measurand = v.get("measurand", "Unknown")
            val = v.get("value", "?")
            unit = v.get("unit", "")
            phase = v.get("phase", "")
            phase_str = f" (phase {phase})" if phase else ""
            self.logger.display(f"    {measurand}: {val} {unit}{phase_str}")

    def enumerate_connectors(self):
        """
        Enumerate connectors and their status.

        For OCPP 1.6: Sends TriggerMessage(StatusNotification) for connector IDs 0-10
        and collects responses to discover active connectors.

        For OCPP 2.0.1: Uses GetBaseReport to discover EVSE/connector topology.
        """
        if not self.conn:
            return

        version = self.results["data"].get("ocpp_version", "1.6")
        self.logger.display("[Connector Enumeration]")
        self.logger.debug(f"Enumerating connectors (version={version})")

        connectors = {}

        if version and version.startswith("2."):
            self.logger.debug("Using OCPP 2.0.1 connector enumeration (GetBaseReport)")
            connectors = self._enumerate_connectors_v201()
        else:
            self.logger.debug("Using OCPP 1.6 connector enumeration (StatusNotification trigger)")
            connectors = self._enumerate_connectors_v16()

        connector_count = len(
            [c for c in connectors.values() if isinstance(c, dict) and c.get("found")]
        )
        self.logger.display(f"  Found {connector_count} connector(s)")

        self.results["data"]["connectors"] = connectors

    def _enumerate_connectors_v16(self) -> Dict[str, Any]:
        """
        Enumerate connectors via StatusNotification TriggerMessage (OCPP 1.6).

        Returns:
            Dictionary mapping connector IDs to status information
        """
        connectors = {}
        max_connector_id = getattr(self.args, "max_connector_id", 10) or 10

        for cid in range(0, max_connector_id + 1):
            try:
                trigger_msg = self._build_trigger_message("StatusNotification", cid)
                response = self.scanner._send_and_receive(self.conn, trigger_msg, timeout=3)

                if response is None:
                    continue

                msg_type, _, payload = self._parse_message(response)

                if msg_type == MessageType.CALLRESULT:
                    status = payload.get("status", "Unknown")
                    connectors[str(cid)] = {"found": True, "trigger_status": status}

                    # Try to receive the follow-up StatusNotification from CP
                    status_info = self._receive_status_notification()
                    if status_info:
                        connectors[str(cid)].update(status_info)
                        cp_status = status_info.get("status", "Unknown")
                        self.logger.display(f"  Connector {cid}: {cp_status}")
                    else:
                        self.logger.display(f"  Connector {cid}: trigger {status}")

                elif msg_type == MessageType.CALLERROR:
                    error_code = payload.get("error_code", "")
                    if error_code not in ("NotImplemented", "NotSupported"):
                        # Error other than not-implemented may indicate valid connector
                        connectors[str(cid)] = {
                            "found": True,
                            "trigger_status": "error",
                            "error_code": error_code,
                        }

            except Exception as e:
                self.logger.debug(f"Connector {cid} probe failed: {e}")

        return connectors

    def _enumerate_connectors_v201(self) -> Dict[str, Any]:
        """
        Enumerate connectors via GetBaseReport (OCPP 2.0.1).

        Returns:
            Dictionary with EVSE/connector topology information
        """
        connectors = {}

        try:
            report_msg = self._build_get_base_report(request_id=1, report_base="FullInventory")
            response = self.scanner._send_and_receive(self.conn, report_msg, timeout=5)

            if response is None:
                self.logger.display("  No response to GetBaseReport")
                return connectors

            msg_type, _, payload = self._parse_message(response)

            if msg_type == MessageType.CALLRESULT:
                status = payload.get("status", "Unknown")
                self.logger.display(f"  GetBaseReport: {status}")
                connectors["report_status"] = status

                if status == "Accepted":
                    connectors["found"] = True

            elif msg_type == MessageType.CALLERROR:
                error_code = payload.get("error_code", "")
                self.logger.display(f"  GetBaseReport: {error_code}")
                connectors["error_code"] = error_code

        except Exception as e:
            self.logger.debug(f"GetBaseReport failed: {e}")

        # Fall back to StatusNotification approach
        if not connectors.get("found"):
            self.logger.display("  Falling back to StatusNotification enumeration")
            connectors.update(self._enumerate_connectors_v16())

        return connectors

    def get_local_list_version(self):
        """
        Query the local authorization list version via GetLocalListVersion.

        This reveals whether a local auth list is configured and its version.
        """
        if not self.conn:
            return

        self.logger.debug("Sending GetLocalListVersion")
        self.logger.display("[LocalList Version]")

        try:
            msg = self._build_get_local_list_version()
            response = self.scanner._send_and_receive(self.conn, msg, timeout=5)

            if response is None:
                self.logger.display("  No response to GetLocalListVersion")
                return

            msg_type, _, payload = self._parse_message(response)

            if msg_type == MessageType.CALLRESULT:
                version = payload.get("listVersion", -1)
                self.logger.display(f"  Local auth list version: {version}")
                if version == -1:
                    self.logger.display("  (No local authorization list configured)")
                self.results["data"]["local_list_version"] = version

            elif msg_type == MessageType.CALLERROR:
                error_code = payload.get("error_code", "")
                self.logger.display(f"  GetLocalListVersion: {error_code}")

        except Exception as e:
            self.logger.debug(f"GetLocalListVersion failed: {e}")

    def get_composite_schedule(self):
        """
        Query the composite charging schedule via GetCompositeSchedule.

        Reveals active charging profiles and rate limits for a connector.
        """
        if not self.conn:
            return

        connector_id = getattr(self.args, "connector_id", 1) or 1
        self.logger.debug(f"Sending GetCompositeSchedule for connector {connector_id}")
        self.logger.display(f"[Composite Schedule] Connector {connector_id}")

        try:
            msg = self._build_get_composite_schedule(connector_id=connector_id, duration=3600)
            response = self.scanner._send_and_receive(self.conn, msg, timeout=5)

            if response is None:
                self.logger.display("  No response to GetCompositeSchedule")
                return

            msg_type, _, payload = self._parse_message(response)

            if msg_type == MessageType.CALLRESULT:
                status = payload.get("status", "Unknown")
                self.logger.display(f"  GetCompositeSchedule: {status}")

                schedule = payload.get("chargingSchedule")
                if schedule:
                    rate_unit = schedule.get("chargingRateUnit", "?")
                    periods = schedule.get("chargingSchedulePeriod", [])
                    self.logger.display(f"  Rate unit: {rate_unit}")
                    for period in periods[:5]:
                        start = period.get("startPeriod", 0)
                        limit = period.get("limit", "?")
                        self.logger.display(f"    Period @{start}s: limit={limit} {rate_unit}")

                self.results["data"]["composite_schedule"] = {
                    "status": status,
                    "connector_id": connector_id,
                    "schedule": schedule,
                }

            elif msg_type == MessageType.CALLERROR:
                error_code = payload.get("error_code", "")
                self.logger.display(f"  GetCompositeSchedule: {error_code}")

        except Exception as e:
            self.logger.debug(f"GetCompositeSchedule failed: {e}")

    def get_installed_certs(self):
        """
        Query installed certificate IDs via GetInstalledCertificateIds (OCPP 2.0.1).

        Reveals PKI configuration and installed certificates on the charge point.
        """
        if not self.conn:
            return

        self.logger.debug("Sending GetInstalledCertificateIds")
        self.logger.display("[Installed Certificates]")

        try:
            msg = self._build_get_installed_certificate_ids()
            response = self.scanner._send_and_receive(self.conn, msg, timeout=5)

            if response is None:
                self.logger.display("  No response to GetInstalledCertificateIds")
                return

            msg_type, _, payload = self._parse_message(response)

            if msg_type == MessageType.CALLRESULT:
                status = payload.get("status", "Unknown")
                cert_info = payload.get("certificateHashDataChain", [])
                self.logger.display(f"  GetInstalledCertificateIds: {status}")

                if cert_info:
                    self.logger.display(f"  Installed certificates ({len(cert_info)}):")
                    for cert in cert_info[:10]:
                        cert_type = cert.get("certificateType", "Unknown")
                        hash_data = cert.get("certificateHashData", {})
                        serial = hash_data.get("serialNumber", "?")
                        pem_data = cert.get("certificate", "")

                        self.logger.display(f"    {cert_type}: serial={serial}")

                        # Parse PEM certificate through central display function
                        if pem_data:
                            self._display_cert_pem(pem_data, cert_type)

                self.results["data"]["installed_certs"] = {
                    "status": status,
                    "certificates": cert_info,
                }

            elif msg_type == MessageType.CALLERROR:
                error_code = payload.get("error_code", "")
                self.logger.display(f"  GetInstalledCertificateIds: {error_code}")

        except Exception as e:
            self.logger.debug(f"GetInstalledCertificateIds failed: {e}")

    def _display_cert_pem(self, pem_data: str, cert_type: str):
        """Parse a PEM certificate via the central cert display/store function."""
        if not _security_findings.is_available:
            self.logger.debug("cryptography not available, skipping cert parse")
            return
        try:
            display_cert_info = _security_findings.display_cert_info
            target = self.results["data"].get("target_url", self.ip)
            cert_bytes = pem_data.encode("ascii") if isinstance(pem_data, str) else pem_data
            cert_results = self.results["data"].setdefault("installed_cert_details", {})
            display_cert_info(
                logger=self.logger,
                cert=cert_bytes,
                protocol="ocpp",
                target=target,
                results=cert_results,
                verbose=True,
            )
        except Exception as e:
            self.logger.debug(f"Certificate parse failed for {cert_type}: {e}")

    # ==================================================================
    # WebSocket Path Brute-Forcing
    # ==================================================================

    def _load_ws_paths(self) -> List[str]:
        """
        Load WebSocket paths for brute-forcing.

        ``--ws-brute`` accepts an optional file path.  When a path is given
        it is read as the wordlist; otherwise the built-in
        ``src/oida/data/ocpp/ws_paths.txt`` (shipped with the package) is
        tried, falling back to a hardcoded list.

        Returns:
            List of path strings to test
        """
        ws_brute = getattr(self.args, "ws_brute", None)

        # --ws-brute /some/file.txt  →  ws_brute == "/some/file.txt"
        if isinstance(ws_brute, str):
            self.logger.debug(f"Loading WS paths from user file: {ws_brute}")
            return self._read_wordlist_file(ws_brute)

        # Try built-in wordlist shipped with OIDA (packaged under oida/data/)
        try:
            builtin_path = _pkg_root() / "data" / "ocpp" / "ws_paths.txt"
            if builtin_path.is_file():
                self.logger.debug(f"Loading WS paths from built-in file: {builtin_path}")
                return self._read_wordlist_file(str(builtin_path))
        except Exception as e:
            self.logger.debug(f"Failed to locate built-in wordlist: {e}")

        self.logger.debug("Using default hardcoded WS paths")
        return self._get_default_ws_paths()

    @staticmethod
    def _read_wordlist_file(filepath: str) -> List[str]:
        """
        Read paths from a wordlist file, stripping comments and blanks.

        Args:
            filepath: Path to the wordlist file

        Returns:
            List of path strings
        """
        paths = []
        try:
            with open(filepath, "r") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        paths.append(line)
        except (IOError, OSError):
            # Silently fall back if file can't be read
            pass
        return paths if paths else DiscoveryMixin._get_default_ws_paths()

    @staticmethod
    def _get_default_ws_paths() -> List[str]:
        """
        Return a hardcoded list of the most common OCPP WebSocket paths.

        This serves as a fallback when the wordlist file is unavailable.

        Returns:
            List of path strings
        """
        return [
            "/",
            "/steve/websocket/CentralSystemService",
            "/ocpp",
            "/ws",
            "/websocket",
            "/ocpp/ws",
            "/ocpp/websocket",
            "/ws/ocpp",
            "/ocpp/v16",
            "/ocpp/v201",
            "/ocpp16",
            "/ocpp201",
            "/ocpp/cp",
            "/ocpp/cp/socket/15",
            "/ocpp/cp/socket/16",
            "/webServices/ocpp",
            "/services/CentralSystemService",
            "/CentralSystemService",
            "/api/ocpp",
            "/api/v1/ocpp",
            "/api/ws",
            "/cp",
            "/csms",
            "/chargepoint",
            "/ev",
            "/evse",
            "/station",
            "/gateway/ocpp",
            "/connect",
            "/ocpp-j",
            "/json/ocpp",
            "/v16",
            "/v201",
            "/central-system",
            "/cs",
        ]

    def ws_brute_force(self):
        """
        Brute-force WebSocket paths to discover OCPP endpoints.

        Tries each path from the wordlist against the target, appending the
        charge point ID.  Reports reachable endpoints with OCPP version and
        auth status.  Shows live progress via ``self.logger.progress()``.
        """
        self.logger.debug("Starting WebSocket path brute-force")
        self.logger.display("[WebSocket Path Brute-Force]")

        # --- resolve base URL ---
        target = getattr(self.args, "target", None) or self.ip
        port = getattr(self.args, "port", None) or 9000
        cp_id = getattr(self.args, "charge_point_id", "CP_SCANNER_001")

        if target and (target.startswith("ws://") or target.startswith("wss://")):
            from urllib.parse import urlparse

            parsed = urlparse(target)
            scheme = parsed.scheme
            host = parsed.hostname or self.ip
            port = parsed.port or port
            base_url = f"{scheme}://{host}:{port}"
        else:
            scheme = "wss" if getattr(self.args, "tls", False) else "ws"
            host = target or self.ip
            if ":" in host and not host.startswith("["):
                parts = host.rsplit(":", 1)
                if parts[1].isdigit():
                    host = parts[0]
                    port = int(parts[1])
            base_url = f"{scheme}://{host}:{port}"

        paths = self._load_ws_paths()
        total = len(paths)

        found_endpoints = []
        tested = 0
        rate_delay = getattr(self.args, "brute_rate", 0.1)
        self.logger.debug(
            f"WS brute: base={base_url}, cp_id={cp_id}, paths={total}, delay={rate_delay}s"
        )
        self.logger.display(f"  Target: {base_url}  CP-ID: {cp_id}  Paths: {total}")

        for path in paths:
            tested += 1
            self.logger.progress(tested, total, len(found_endpoints))

            try:
                result = self.scanner._probe_path(base_url, path, cp_id)

                if result.get("reachable"):
                    version = result.get("version", "")
                    status_code = result.get("status_code")

                    version_str = f" OCPP {version}" if version else ""
                    auth_str = " [AUTH REQUIRED]" if status_code in (401, 403) else ""

                    # newline to break out of progress, then print hit
                    self.logger.progress(tested, total, len(found_endpoints), end="\n")
                    self.logger.success(
                        f"  {path} -> {result.get('reason', '')}{version_str}{auth_str}"
                    )

                    found_endpoints.append(
                        {
                            "path": path,
                            "url": result.get("url", ""),
                            "reachable": True,
                            "version": version,
                            "subprotocol": result.get("subprotocol", ""),
                            "status_code": status_code,
                            "reason": result.get("reason", ""),
                        }
                    )

            except Exception as e:
                self.logger.debug(f"  Path probe {path} failed: {e}")

            if rate_delay > 0:
                time.sleep(rate_delay)

        # final newline after progress
        self.logger.progress(tested, total, len(found_endpoints), end="\n")

        # --- summary ---
        found_count = len(found_endpoints)
        authed = sum(1 for e in found_endpoints if e.get("status_code") in (401, 403))
        open_count = found_count - authed

        self.logger.display(
            f"  Result: {found_count} endpoint(s) — {open_count} open, {authed} auth-required"
        )

        if found_endpoints:
            for ep in found_endpoints:
                v = f" (OCPP {ep['version']})" if ep.get("version") else ""
                s = f" [{ep['status_code']}]" if ep.get("status_code") else ""
                self.logger.display(f"    {ep['url']}{v}{s}")

        # --- store ---
        self.results["data"]["ws_brute"] = {
            "base_url": base_url,
            "charge_point_id": cp_id,
            "paths_tested": tested,
            "endpoints_found": found_count,
            "open_endpoints": open_count,
            "auth_required_endpoints": authed,
            "endpoints": found_endpoints,
        }

        if open_count > 0:
            open_eps = [e for e in found_endpoints if e.get("status_code") not in (401, 403)]
            paths_str = ", ".join(e.get("path", "") for e in open_eps[:5])
            self._add_finding(
                "MEDIUM",
                f"OCPP endpoints discovered via path brute-force ({open_count})",
                f"Open WebSocket endpoints found at: {paths_str}",
            )

    def _receive_status_notification(self) -> Optional[Dict[str, Any]]:
        """
        Try to receive a StatusNotification CALL from the charge point.

        Returns:
            Status information dictionary or None
        """
        try:
            loop = getattr(self.scanner, "_event_loop", None)
            if not loop or loop.is_closed():
                return None

            import asyncio

            async def _recv():
                try:
                    return await asyncio.wait_for(self.conn.recv(), timeout=2)
                except asyncio.TimeoutError:
                    self.logger.debug("No async StatusNotification received within timeout")
                    return None

            raw = loop.run_until_complete(_recv())
            if raw is None:
                return None

            msg_type, msg_id, payload = self._parse_message(raw)

            if msg_type == MessageType.CALL:
                action = payload.get("action", "")
                if action == "StatusNotification":
                    p = payload.get("payload", {})
                    info = {
                        "status": p.get("status", "Unknown"),
                        "error_code": p.get("errorCode", "NoError"),
                        "connector_id": p.get("connectorId", 0),
                    }

                    # Send CALLRESULT acknowledgement
                    ack = self._build_call_result(msg_id, {})
                    try:
                        self.scanner._send_and_receive(self.conn, ack, timeout=1)
                    except Exception as e:
                        self.logger.debug(f"Failed to send acknowledgement: {e}")

                    return info

        except Exception as e:
            self.logger.debug(f"StatusNotification receive failed: {e}")

        return None
