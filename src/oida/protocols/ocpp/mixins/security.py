"""
OCPP Security Mixin

Provides explicit security check methods for the NXC-style OCPP connection class.
Each check is triggered by its own CLI flag.
"""

import base64
import time

from oida.utils.common_types import Category

from ..constants import (
    SECURITY_CONFIG_KEYS,
    SENSITIVE_CONFIG_KEYS,
    HARMLESS_CONFIG_KEY,
    MessageType,
    FAKE_ID_TAG,
    FAKE_FIRMWARE_URL,
    FAKE_FIRMWARE_RETRIEVE_DATE,
    FAKE_DIAGNOSTICS_URL,
    FAKE_LOG_URL,
    SAFE_CHARGING_PROFILE_ID,
    SAFE_RESERVATION_ID,
    SAFE_TRANSACTION_ID,
    FAKE_NETWORK_PROFILE_URL,
    PROBE_TEST_CERTIFICATE,
    PROBE_DISPLAY_MESSAGE,
    SSRF_PROBE_URLS,
)


class SecurityMixin:
    """Mixin for OCPP security assessment"""

    def _add_finding(self, severity: str, issue: str, description: str):
        """Append a security finding to results."""
        self.logger.debug(f"Security finding: [{severity}] {issue}")
        findings = self.results["data"].setdefault("security_findings", [])
        findings.append({"severity": severity, "issue": issue, "description": description})

    @staticmethod
    def _extract_write_status(payload, version: str) -> str:
        """Extract write status from ChangeConfiguration (1.6) or SetVariables (2.0.1) response."""
        if version.startswith("2."):
            results = payload.get("setVariableResult", [])
            if results:
                return results[0].get("attributeStatus", "Unknown")
            return "Unknown"
        return payload.get("status", "Unknown")

    def _check_tls_certificate(self):
        """Probe the TLS endpoint to retrieve and check the server certificate.

        Runs automatically after connection when wss:// is used.
        Uses the central check_tls_certificate helper (same as IEC 104, Modbus, etc.).
        """
        try:
            from urllib.parse import urlparse

            from ....utils.socket_helpers import check_tls_certificate

            # self.ip is the resolved connection host, but for wss:// targets
            # it can end up holding the raw target URL when resolution fails
            # (e.g. hostname lookups against the full "wss://host/path"
            # string). Derive the bare hostname from the parsed target URL so
            # the TLS probe always dials a real host, not the URL string.
            parsed_host = urlparse(getattr(self, "_target_url", "") or "").hostname
            host = parsed_host or self.ip
            port = getattr(self.args, "port", 443)
            self.logger.debug(f"Checking TLS certificate for {host}:{port}")

            check_tls_certificate(
                host=host,
                port=port,
                logger=self.logger,
                protocol="ocpp",
                timeout=getattr(self.args, "timeout", 5),
                verbose=getattr(self.args, "verbose", 0) or 0,
            )

        except Exception as e:
            self.logger.debug(f"TLS certificate check failed: {e}")

    def _handle_check_auth(self):
        """Check if anonymous connections are accepted (no HTTP Basic Auth).

        create_conn_obj() already reports "Anonymous access" unconditionally
        for every connection made without credentials (it runs regardless of
        --check-auth/--security), so this handler must not re-report the
        same condition -- doing so previously produced two differently
        shaped entries in results["data"]["security_findings"] (one via
        logger.security_finding()/to_list(), one via self._add_finding())
        for the identical underlying issue on every --security run.
        """
        if not self.conn:
            return

        self.logger.debug("Checking authentication status")
        username = getattr(self.args, "username", None)
        if not username:
            self.logger.debug(
                "Anonymous WebSocket connection (already reported by create_conn_obj)"
            )
        else:
            self.logger.display(f"[Auth] Authenticated as {username}")

    def _handle_check_boot(self):
        """Check if BootNotification from unknown CP is accepted."""
        if not self.conn:
            return

        boot = self.results["data"].get("boot_notification", {})
        status = boot.get("status", "")
        self.logger.debug(f"Checking boot notification status: {status}")

        if status == "Accepted":
            self.logger.security_finding(
                "No authentication",
                category=Category.AUTHENTICATION,
                detail="Unknown charge point accepted by CSMS via BootNotification",
            )
            self._add_finding(
                "MEDIUM",
                "BootNotification accepted without authentication",
                "CSMS accepted an unknown charge point registration",
            )
        elif status == "Pending":
            self.logger.display("[Boot] Pending (awaiting manual registration)")
        elif status == "Rejected":
            self.logger.display("[Boot] Rejected (good - unknown CP rejected)")
        else:
            self.logger.display(f"[Boot] Status: {status or 'no response'}")

    def _handle_check_config_keys(self):
        """Check for exposed security configuration keys."""
        if not self.conn:
            return

        config = self.results["data"].get("configuration", {})
        config_keys = config.get("keys", [])
        self.logger.debug(f"Checking {len(config_keys)} config keys for security issues")

        if not config_keys:
            self.logger.display("[Config Keys] No configuration data (run -c first)")
            return

        for key_info in config_keys:
            key_name = key_info.get("key", "")
            key_value = key_info.get("value", "")
            readonly = key_info.get("readonly", True)

            if key_name == "AuthorizationKey" and key_value:
                self.logger.security_finding(
                    "Insecure configuration",
                    category=Category.CONFIGURATION,
                    detail="AuthorizationKey exposed in configuration",
                )
                self._add_finding(
                    "CRITICAL",
                    "AuthorizationKey exposed in configuration",
                    f"AuthorizationKey readable: {key_value[:4]}...",
                )

            if key_name in SECURITY_CONFIG_KEYS and not readonly:
                self.logger.security_finding(
                    "Writable access",
                    category=Category.ACCESS_CONTROL,
                    detail=f"Security config key '{key_name}' is writable",
                )
                self._add_finding(
                    "MEDIUM",
                    f"Security config key '{key_name}' is writable",
                    f"Configuration key {key_name} can be modified",
                )

    def _handle_version_enumeration(self):
        """Enumerate supported OCPP versions via subprotocol probing."""
        self.logger.debug("Starting version enumeration via subprotocol probing")
        self.logger.display("[Version Enumeration]")

        supported_versions = []
        target_url = self.results["data"].get("target_url", "")

        for version_label, subprotocol in [
            ("1.6", "ocpp1.6"),
            ("2.0.1", "ocpp2.0.1"),
            ("2.1", "ocpp2.1"),
        ]:
            try:
                self.logger.debug(f"Probing OCPP {version_label} ({subprotocol})")
                result = self.scanner._probe_version(target_url, subprotocol)
                if result.get("supported"):
                    supported_versions.append(version_label)
                    self.logger.debug(
                        f"OCPP {version_label}: supported (reason={result.get('reason')})"
                    )
                    self.logger.display(f"  OCPP {version_label}: Supported")
                else:
                    reason = result.get("reason", "rejected")
                    self.logger.debug(f"OCPP {version_label}: not supported ({reason})")
                    self.logger.display(f"  OCPP {version_label}: Not supported ({reason})")
            except Exception as e:
                self.logger.debug(f"Version probe {version_label} failed: {e}")
                self.logger.display(f"  OCPP {version_label}: Probe failed")

        self.logger.debug(f"Version enumeration complete: {supported_versions}")
        self.results["data"]["supported_versions"] = supported_versions

    # ==================================================================
    # Active security probes (require --security or individual flags)
    # ==================================================================

    def test_charging_profile_write(self):
        """
        Test if unauthorized charging profile manipulation is possible.

        Attempts to set a TxDefaultProfile with a very low amperage (1A) via
        SetChargingProfile, then immediately clears it via ClearChargingProfile.
        Reports whether the profile change was accepted without authorization.

        Safety: The profile is always cleared immediately after setting.
        """
        if not self.conn:
            return

        self.logger.display("[Security] Charging profile write test")

        connector_id = getattr(self.args, "connector_id", 1) or 1
        profile_id = SAFE_CHARGING_PROFILE_ID
        self.logger.debug(
            f"Security probe: SetChargingProfile (connector={connector_id}, profile_id={profile_id})"
        )
        result_data = {"set_status": None, "clear_status": None}

        try:
            # Step 1: Attempt to set a low-amperage TxDefaultProfile
            set_msg = self._build_set_charging_profile(
                connector_id=connector_id,
                profile_id=profile_id,
                stack_level=0,
                purpose="TxDefaultProfile",
                rate_unit="A",
                limit=1.0,
            )

            response = self.scanner._send_and_receive(self.conn, set_msg, timeout=5)
            if response is None:
                self.logger.display("  SetChargingProfile: no response")
                result_data["set_status"] = "no_response"
            else:
                msg_type, _, payload = self._parse_message(response)

                if msg_type == MessageType.CALLRESULT:
                    status = payload.get("status", "Unknown")
                    result_data["set_status"] = status
                    if status == "Accepted":
                        self.logger.warning(
                            "  SetChargingProfile: ACCEPTED (unauthenticated write possible)"
                        )
                        self._add_finding(
                            "HIGH",
                            "Unauthorized charging profile write accepted",
                            "SetChargingProfile with TxDefaultProfile (1A) was accepted "
                            "without authentication. Rate manipulation attack possible.",
                        )
                    else:
                        self.logger.display(f"  SetChargingProfile: {status}")

                elif msg_type == MessageType.CALLERROR:
                    error_code = payload.get("error_code", "")
                    result_data["set_status"] = f"error:{error_code}"
                    self.logger.display(f"  SetChargingProfile: {error_code}")

        except Exception as e:
            self.logger.debug(f"SetChargingProfile failed: {e}")
            result_data["set_status"] = f"exception:{e}"

        # Step 2: Always attempt to clear the profile (cleanup)
        try:
            clear_msg = self._build_clear_charging_profile(profile_id=profile_id)
            response = self.scanner._send_and_receive(self.conn, clear_msg, timeout=5)

            if response is not None:
                msg_type, _, payload = self._parse_message(response)
                if msg_type == MessageType.CALLRESULT:
                    result_data["clear_status"] = payload.get("status", "Unknown")
                elif msg_type == MessageType.CALLERROR:
                    result_data["clear_status"] = payload.get("error_code", "")
            else:
                result_data["clear_status"] = "no_response"

            self.logger.debug(f"  ClearChargingProfile: {result_data['clear_status']}")

        except Exception as e:
            self.logger.debug(f"ClearChargingProfile cleanup failed: {e}")
            result_data["clear_status"] = f"exception:{e}"

        self.results["data"]["charging_profile_write"] = result_data

    def test_remote_transaction_control(self):
        """
        Test if unauthorized remote transaction start is possible.

        Sends RemoteStartTransaction with a clearly fake IdTag to check
        if the charger accepts unauthorized session starts.

        Safety: Uses a fake IdTag (OIDA_SEC_TEST_00000000) that will never
        match a real authorization list entry.
        """
        if not self.conn:
            return

        self.logger.display("[Security] Remote transaction control test")

        connector_id = getattr(self.args, "connector_id", 1) or 1
        version = self.results["data"].get("ocpp_version", "1.6") or "1.6"
        self.logger.debug(
            f"Security probe: RemoteStartTransaction (connector={connector_id}, idTag={FAKE_ID_TAG})"
        )
        result_data = {"start_status": None}

        try:
            start_msg = self._build_remote_start_transaction(
                id_tag=FAKE_ID_TAG,
                connector_id=connector_id,
                version=version,
            )

            response = self.scanner._send_and_receive(self.conn, start_msg, timeout=5)
            if response is None:
                self.logger.display("  RemoteStartTransaction: no response")
                result_data["start_status"] = "no_response"
            else:
                msg_type, _, payload = self._parse_message(response)

                if msg_type == MessageType.CALLRESULT:
                    status = payload.get("status", "Unknown")
                    result_data["start_status"] = status
                    if status == "Accepted":
                        self.logger.warning(
                            "  RemoteStartTransaction: ACCEPTED (unauthenticated session start possible)"
                        )
                        self._add_finding(
                            "CRITICAL",
                            "Unauthorized remote transaction start accepted",
                            f"RemoteStartTransaction with fake IdTag '{FAKE_ID_TAG}' was "
                            "accepted. Unauthorized charging sessions can be started.",
                        )
                    else:
                        self.logger.display(f"  RemoteStartTransaction: {status}")

                elif msg_type == MessageType.CALLERROR:
                    error_code = payload.get("error_code", "")
                    result_data["start_status"] = f"error:{error_code}"
                    self.logger.display(f"  RemoteStartTransaction: {error_code}")

        except Exception as e:
            self.logger.debug(f"RemoteStartTransaction failed: {e}")
            result_data["start_status"] = f"exception:{e}"

        self.results["data"]["remote_transaction"] = result_data

    def test_reset_command(self):
        """
        Test if an unauthorized Soft Reset command is accepted.

        Sends a Reset(type=Soft) request. If accepted, this represents an
        availability attack risk -- any unauthenticated party can restart
        the charge point.

        Safety: Only Soft reset is sent, never Hard reset.
        """
        if not self.conn:
            return

        self.logger.display("[Security] Reset command test (Soft only)")
        version = self.results["data"].get("ocpp_version", "1.6") or "1.6"
        self.logger.debug("Security probe: Reset(Soft)")

        result_data = {"reset_status": None, "reset_type": "Soft"}

        try:
            reset_msg = self._build_reset(reset_type="Soft", version=version)

            response = self.scanner._send_and_receive(self.conn, reset_msg, timeout=5)
            if response is None:
                self.logger.display("  Reset(Soft): no response")
                result_data["reset_status"] = "no_response"
            else:
                msg_type, _, payload = self._parse_message(response)

                if msg_type == MessageType.CALLRESULT:
                    status = payload.get("status", "Unknown")
                    result_data["reset_status"] = status
                    if status == "Accepted":
                        self.logger.warning(
                            "  Reset(Soft): ACCEPTED (unauthenticated reset possible)"
                        )
                        self._add_finding(
                            "HIGH",
                            "Unauthorized soft reset accepted",
                            "Reset(Soft) command was accepted without authentication. "
                            "An attacker can restart the charge point (denial of service).",
                        )
                    else:
                        self.logger.display(f"  Reset(Soft): {status}")

                elif msg_type == MessageType.CALLERROR:
                    error_code = payload.get("error_code", "")
                    result_data["reset_status"] = f"error:{error_code}"
                    self.logger.display(f"  Reset(Soft): {error_code}")

        except Exception as e:
            self.logger.debug(f"Reset command failed: {e}")
            result_data["reset_status"] = f"exception:{e}"

        self.results["data"]["reset_test"] = result_data

    def test_unlock_connector(self):
        """
        Test if an unauthorized UnlockConnector command is accepted.

        If accepted, this represents a physical access bypass risk --
        an attacker can unlock the charging connector remotely.
        """
        if not self.conn:
            return

        self.logger.display("[Security] UnlockConnector test")

        connector_id = getattr(self.args, "connector_id", 1) or 1
        version = self.results["data"].get("ocpp_version", "1.6") or "1.6"
        self.logger.debug(f"Security probe: UnlockConnector(connector={connector_id})")
        result_data = {"unlock_status": None, "connector_id": connector_id}

        try:
            unlock_msg = self._build_unlock_connector(connector_id=connector_id, version=version)

            response = self.scanner._send_and_receive(self.conn, unlock_msg, timeout=5)
            if response is None:
                self.logger.display("  UnlockConnector: no response")
                result_data["unlock_status"] = "no_response"
            else:
                msg_type, _, payload = self._parse_message(response)

                if msg_type == MessageType.CALLRESULT:
                    status = payload.get("status", "Unknown")
                    result_data["unlock_status"] = status
                    if status == "Unlocked":
                        self.logger.warning(
                            f"  UnlockConnector({connector_id}): UNLOCKED "
                            "(unauthenticated remote unlock possible)"
                        )
                        self._add_finding(
                            "HIGH",
                            "Unauthorized connector unlock accepted",
                            f"UnlockConnector({connector_id}) was accepted. "
                            "Connector can be unlocked remotely without authorization.",
                        )
                    else:
                        self.logger.display(f"  UnlockConnector({connector_id}): {status}")

                elif msg_type == MessageType.CALLERROR:
                    error_code = payload.get("error_code", "")
                    result_data["unlock_status"] = f"error:{error_code}"
                    self.logger.display(f"  UnlockConnector: {error_code}")

        except Exception as e:
            self.logger.debug(f"UnlockConnector failed: {e}")
            result_data["unlock_status"] = f"exception:{e}"

        self.results["data"]["unlock_connector"] = result_data

    def test_firmware_update(self):
        """
        Test if an unauthorized firmware update command is accepted.

        Sends UpdateFirmware with a clearly invalid/dummy URL (http://0.0.0.0/test.bin).
        If accepted without authentication, this represents a supply chain attack vector.

        Safety: URL points to 0.0.0.0 which is non-routable and will never
        result in an actual firmware download.
        """
        if not self.conn:
            return

        self.logger.display("[Security] Firmware update injection test")
        self.logger.debug(f"Security probe: UpdateFirmware (url={FAKE_FIRMWARE_URL})")

        result_data = {"update_status": None, "location": FAKE_FIRMWARE_URL}

        version = self.results["data"].get("ocpp_version", "1.6") or "1.6"
        try:
            fw_msg = self._build_update_firmware(
                location=FAKE_FIRMWARE_URL,
                retrieve_date=FAKE_FIRMWARE_RETRIEVE_DATE,
                retries=0,
                version=version,
            )

            response = self.scanner._send_and_receive(self.conn, fw_msg, timeout=5)
            if response is None:
                self.logger.display("  UpdateFirmware: no response")
                result_data["update_status"] = "no_response"
            else:
                msg_type, _, payload = self._parse_message(response)

                if msg_type == MessageType.CALLRESULT:
                    # OCPP 1.6: UpdateFirmware response is empty {} for Accepted
                    result_data["update_status"] = "Accepted"
                    self.logger.warning(
                        "  UpdateFirmware: ACCEPTED (unauthenticated firmware update possible)"
                    )
                    self._add_finding(
                        "CRITICAL",
                        "Unauthorized firmware update accepted",
                        f"UpdateFirmware with dummy URL ({FAKE_FIRMWARE_URL}) was accepted "
                        "without authentication. Supply chain attack vector.",
                    )

                elif msg_type == MessageType.CALLERROR:
                    error_code = payload.get("error_code", "")
                    result_data["update_status"] = f"error:{error_code}"
                    self.logger.display(f"  UpdateFirmware: {error_code}")

        except Exception as e:
            self.logger.debug(f"UpdateFirmware failed: {e}")
            result_data["update_status"] = f"exception:{e}"

        self.results["data"]["firmware_update"] = result_data

    def test_config_write(self):
        """
        Test if configuration keys can be written without authorization.

        Step 1: Read HeartbeatInterval via GetConfiguration, then write the
        same value back via ChangeConfiguration. This is harmless but reveals
        whether config writes are accepted.

        Step 2: Test security-sensitive keys (AuthorizationKey, SecurityProfile,
        AllowOfflineTxForUnknownId) to see if they are writable.
        """
        if not self.conn:
            return

        self.logger.display("[Security] Configuration write test")
        self.logger.debug("Security probe: ChangeConfiguration write access test")

        result_data = {"harmless_write": None, "sensitive_keys": {}}

        result_data["harmless_write"] = self._test_harmless_config_write()
        self._probe_sensitive_keys(result_data["sensitive_keys"])

        self.results["data"]["config_write"] = result_data

    def _read_config_value(self, key_name, timeout=5):
        """
        Read a single configuration key value via GetConfiguration.

        Args:
            key_name: Configuration key to read
            timeout: Request timeout in seconds

        Returns:
            The key value string, or None if not readable
        """
        self.logger.debug(f"Reading config key: {key_name}")
        version = self.results["data"].get("ocpp_version", "1.6") or "1.6"
        try:
            get_msg = self._build_get_configuration(keys=[key_name], version=version)
            response = self.scanner._send_and_receive(self.conn, get_msg, timeout=timeout)

            if response is not None:
                msg_type, _, payload = self._parse_message(response)
                if msg_type == MessageType.CALLRESULT:
                    if version.startswith("2."):
                        # OCPP 2.0.1: GetVariables response
                        for r in payload.get("getVariableResult", []):
                            var = r.get("variable", {}).get("name", "")
                            if var == key_name:
                                attr_status = r.get("attributeStatus", "")
                                if attr_status == "Accepted":
                                    return {
                                        "key": key_name,
                                        "value": r.get("attributeValue", ""),
                                        "readonly": False,
                                    }
                                return {"key": key_name, "value": "", "readonly": True}
                    else:
                        keys = payload.get("configurationKey", [])
                        for k in keys:
                            if k.get("key") == key_name:
                                return k
        except Exception as e:
            self.logger.debug(f"GetConfiguration({key_name}) failed: {e}")

        return None

    def _test_harmless_config_write(self):
        """
        Test config write access using the HeartbeatInterval key.

        Reads the current value, then writes it back unchanged. This is
        harmless but reveals whether config writes are accepted.

        Returns:
            Status string (e.g. "Accepted", "Rejected", "no_response", "error:...")
        """
        key_info = self._read_config_value(HARMLESS_CONFIG_KEY)
        current_value = key_info.get("value", "300") if key_info else "300"
        self.logger.debug(f"Harmless config write: {HARMLESS_CONFIG_KEY}={current_value}")

        version = self.results["data"].get("ocpp_version", "1.6") or "1.6"
        try:
            write_msg = self._build_change_configuration(
                HARMLESS_CONFIG_KEY, current_value, version=version
            )
            response = self.scanner._send_and_receive(self.conn, write_msg, timeout=5)

            if response is None:
                self.logger.display(f"  ChangeConfiguration({HARMLESS_CONFIG_KEY}): no response")
                return "no_response"

            msg_type, _, payload = self._parse_message(response)

            if msg_type == MessageType.CALLRESULT:
                status = self._extract_write_status(payload, version)
                if status == "Accepted":
                    self.logger.security_finding(
                        "Writable access",
                        category=Category.ACCESS_CONTROL,
                        detail=f"ChangeConfiguration({HARMLESS_CONFIG_KEY}) accepted without auth",
                    )
                    self._add_finding(
                        "MEDIUM",
                        "Configuration writes accepted without authentication",
                        f"ChangeConfiguration({HARMLESS_CONFIG_KEY}) was accepted. "
                        "Configuration can be modified without auth.",
                    )
                elif status == "RebootRequired":
                    self.logger.warning(
                        f"  ChangeConfiguration({HARMLESS_CONFIG_KEY}): RebootRequired (writable)"
                    )
                else:
                    self.logger.display(f"  ChangeConfiguration({HARMLESS_CONFIG_KEY}): {status}")
                return status

            elif msg_type == MessageType.CALLERROR:
                error_code = payload.get("error_code", "")
                self.logger.display(f"  ChangeConfiguration({HARMLESS_CONFIG_KEY}): {error_code}")
                return f"error:{error_code}"

        except Exception as e:
            self.logger.debug(f"ChangeConfiguration({HARMLESS_CONFIG_KEY}) failed: {e}")
            return f"exception:{e}"

        return None

    def _probe_sensitive_keys(self, results_dict):
        """
        Probe security-sensitive configuration keys for write access.

        Tests whether keys like AuthorizationKey, SecurityProfile, and
        AllowOfflineTxForUnknownId are writable without authorization.

        Args:
            results_dict: Dictionary to store per-key results into
        """
        self.logger.debug(f"Probing {len(SENSITIVE_CONFIG_KEYS)} sensitive config keys")
        for sensitive_key in SENSITIVE_CONFIG_KEYS:
            try:
                result = self._probe_single_sensitive_key(sensitive_key)
                results_dict[sensitive_key] = result
            except Exception as e:
                self.logger.debug(f"Config write test for {sensitive_key} failed: {e}")
                results_dict[sensitive_key] = f"exception:{e}"

    def _probe_single_sensitive_key(self, sensitive_key):
        """
        Probe a single sensitive configuration key for write access.

        Args:
            sensitive_key: Configuration key name to probe

        Returns:
            Status string describing the result
        """
        self.logger.debug(f"Probing sensitive key: {sensitive_key}")
        # Read the current value
        key_info = self._read_config_value(sensitive_key, timeout=3)

        if key_info is not None:
            readonly = key_info.get("readonly", True)
            if readonly:
                self.logger.display(f"  {sensitive_key}: readonly (safe)")
                return "readonly"
            key_value = key_info.get("value", "")
        else:
            key_value = None

        if key_value is None:
            # Can't read it, try a probe write with a dummy value.
            # For AuthorizationKey we don't attempt a write (too risky), and
            # for SecurityProfile a fabricated "0" would actually *perform*
            # a security downgrade (TLS/auth off) with no known-good value
            # to restore afterwards — never write a value we didn't read.
            if sensitive_key in ("AuthorizationKey", "SecurityProfile"):
                return "skipped"
            key_value = "0"

        # Attempt to write the same value back (or 0 for unknown keys)
        version = self.results["data"].get("ocpp_version", "1.6") or "1.6"
        write_msg = self._build_change_configuration(sensitive_key, key_value, version=version)
        response = self.scanner._send_and_receive(self.conn, write_msg, timeout=3)

        if response is None:
            return "no_response"

        msg_type, _, payload = self._parse_message(response)

        if msg_type == MessageType.CALLRESULT:
            status = self._extract_write_status(payload, version)
            if status in ("Accepted", "RebootRequired"):
                self.logger.security_finding(
                    "Writable access",
                    category=Category.ACCESS_CONTROL,
                    detail=f"Security-sensitive key '{sensitive_key}' is writable ({status})",
                )
                self._add_finding(
                    "CRITICAL" if sensitive_key == "AuthorizationKey" else "HIGH",
                    f"Security-sensitive key '{sensitive_key}' is writable",
                    f"ChangeConfiguration({sensitive_key}) returned {status}. "
                    "Security configuration can be modified without auth.",
                )
            else:
                self.logger.display(f"  {sensitive_key}: {status}")
            return status

        elif msg_type == MessageType.CALLERROR:
            error_code = payload.get("error_code", "")
            self.logger.display(f"  {sensitive_key}: {error_code}")
            return f"error:{error_code}"

        return None

    # ==================================================================
    # Additional active security probes
    # ==================================================================

    def test_availability(self):
        """
        Test if an unauthorized ChangeAvailability command is accepted.

        Sets connector to Inoperative, then immediately restores to Operative.
        If accepted, this represents a DoS attack vector -- any unauthenticated
        party can take connectors or the entire charge point offline.

        Safety: Always restores to Operative immediately after testing.
        """
        if not self.conn:
            return

        self.logger.display("[Security] ChangeAvailability test")

        connector_id = getattr(self.args, "connector_id", 0)
        version = self.results["data"].get("ocpp_version", "1.6") or "1.6"
        self.logger.debug(
            f"Security probe: ChangeAvailability(Inoperative) on connector {connector_id}"
        )
        result_data = {"set_status": None, "restore_status": None}

        # Step 1: Try to set Inoperative
        try:
            msg = self._build_change_availability(
                connector_id=connector_id, availability_type="Inoperative", version=version
            )
            response = self.scanner._send_and_receive(self.conn, msg, timeout=5)

            if response is None:
                self.logger.display("  ChangeAvailability(Inoperative): no response")
                result_data["set_status"] = "no_response"
            else:
                msg_type, _, payload = self._parse_message(response)

                if msg_type == MessageType.CALLRESULT:
                    status = payload.get("status", "Unknown")
                    result_data["set_status"] = status
                    if status in ("Accepted", "Scheduled"):
                        self.logger.warning(
                            f"  ChangeAvailability(Inoperative): {status} "
                            "(unauthenticated availability change possible)"
                        )
                        self._add_finding(
                            "HIGH",
                            "Unauthorized ChangeAvailability accepted",
                            f"ChangeAvailability(Inoperative) on connector {connector_id} "
                            f"was {status}. Attacker can disable charging.",
                        )
                    else:
                        self.logger.display(f"  ChangeAvailability(Inoperative): {status}")

                elif msg_type == MessageType.CALLERROR:
                    error_code = payload.get("error_code", "")
                    result_data["set_status"] = f"error:{error_code}"
                    self.logger.display(f"  ChangeAvailability: {error_code}")

        except Exception as e:
            self.logger.debug(f"ChangeAvailability failed: {e}")
            result_data["set_status"] = f"exception:{e}"

        # Step 2: Always restore to Operative (cleanup)
        try:
            restore_msg = self._build_change_availability(
                connector_id=connector_id, availability_type="Operative", version=version
            )
            response = self.scanner._send_and_receive(self.conn, restore_msg, timeout=5)

            if response is not None:
                msg_type, _, payload = self._parse_message(response)
                if msg_type == MessageType.CALLRESULT:
                    result_data["restore_status"] = payload.get("status", "Unknown")
                elif msg_type == MessageType.CALLERROR:
                    result_data["restore_status"] = payload.get("error_code", "")
            else:
                result_data["restore_status"] = "no_response"

            self.logger.debug(f"  ChangeAvailability(Operative): {result_data['restore_status']}")

        except Exception as e:
            self.logger.debug(f"ChangeAvailability restore failed: {e}")
            result_data["restore_status"] = f"exception:{e}"

        self.results["data"]["availability_test"] = result_data

    def test_clear_cache(self):
        """
        Test if an unauthorized ClearCache command is accepted.

        If accepted, this forces the charge point to perform online authorization
        for all subsequent transactions, which can be used for DoS if the
        network connection to the CSMS is disrupted.
        """
        if not self.conn:
            return

        self.logger.display("[Security] ClearCache test")
        self.logger.debug("Security probe: ClearCache")

        result_data = {"status": None}

        try:
            msg = self._build_clear_cache()
            response = self.scanner._send_and_receive(self.conn, msg, timeout=5)

            if response is None:
                self.logger.display("  ClearCache: no response")
                result_data["status"] = "no_response"
            else:
                msg_type, _, payload = self._parse_message(response)

                if msg_type == MessageType.CALLRESULT:
                    status = payload.get("status", "Unknown")
                    result_data["status"] = status
                    if status == "Accepted":
                        self.logger.warning(
                            "  ClearCache: ACCEPTED (unauthenticated cache clear possible)"
                        )
                        self._add_finding(
                            "MEDIUM",
                            "Unauthorized ClearCache accepted",
                            "ClearCache was accepted without authentication. "
                            "Local authorization cache was cleared, forcing "
                            "network-dependent auth for all transactions.",
                        )
                    else:
                        self.logger.display(f"  ClearCache: {status}")

                elif msg_type == MessageType.CALLERROR:
                    error_code = payload.get("error_code", "")
                    result_data["status"] = f"error:{error_code}"
                    self.logger.display(f"  ClearCache: {error_code}")

        except Exception as e:
            self.logger.debug(f"ClearCache failed: {e}")
            result_data["status"] = f"exception:{e}"

        self.results["data"]["clear_cache"] = result_data

    def test_diagnostics(self):
        """
        Test if GetDiagnostics/GetLog accepts an attacker-controlled upload URL (SSRF).

        For OCPP 1.6: Sends GetDiagnostics with a dummy upload URL.
        For OCPP 2.0.1: Sends GetLog with a dummy upload URL.

        If accepted, the charge point will attempt to upload diagnostics/logs
        to the attacker's server -- a Server-Side Request Forgery (SSRF) vector.

        Safety: URL points to 0.0.0.0 which is non-routable.
        """
        if not self.conn:
            return

        self.logger.display("[Security] Diagnostics/Log upload SSRF test")

        version = self.results["data"].get("ocpp_version", "1.6") or "1.6"
        result_data = {"status": None, "method": None}

        try:
            if version.startswith("2."):
                self.logger.debug(
                    f"Security probe: GetLog (OCPP 2.x SSRF test, url={FAKE_LOG_URL})"
                )
                # OCPP 2.0.1: GetLog
                result_data["method"] = "GetLog"
                msg = self._build_get_log(
                    log_type="DiagnosticsLog",
                    request_id=1,
                    location=FAKE_LOG_URL,
                )
            else:
                self.logger.debug(
                    f"Security probe: GetDiagnostics (OCPP 1.6 SSRF test, url={FAKE_DIAGNOSTICS_URL})"
                )
                # OCPP 1.6: GetDiagnostics
                result_data["method"] = "GetDiagnostics"
                msg = self._build_get_diagnostics(location=FAKE_DIAGNOSTICS_URL)

            response = self.scanner._send_and_receive(self.conn, msg, timeout=5)
            method = result_data["method"]

            if response is None:
                self.logger.display(f"  {method}: no response")
                result_data["status"] = "no_response"
            else:
                msg_type, _, payload = self._parse_message(response)

                if msg_type == MessageType.CALLRESULT:
                    # GetLog returns {"status": "Accepted"} on accept.
                    # GetDiagnostics.conf's fileName is OPTIONAL per the OCPP
                    # 1.6 spec -- an empty {} CALLRESULT means the CP
                    # acknowledged the request but is NOT going to upload
                    # anything (e.g. no diagnostics available). Only a
                    # non-empty fileName means it actually intends to upload
                    # to our attacker-controlled URL; treating every
                    # CALLRESULT as "Accepted" produced a false HIGH finding
                    # for any CP that merely ack'd the request.
                    if version.startswith("2."):
                        status = payload.get("status", "Accepted")
                    elif payload.get("fileName"):
                        status = "Accepted"
                    else:
                        status = "AcceptedNoUpload"

                    result_data["status"] = status
                    if status == "Accepted":
                        self.logger.warning(
                            f"  {method}: ACCEPTED (attacker-controlled upload URL accepted)"
                        )
                        self._add_finding(
                            "HIGH",
                            f"Unauthorized {method} accepted (SSRF)",
                            f"{method} with attacker-controlled upload URL was accepted. "
                            "Charge point will upload diagnostics/logs to arbitrary URL. "
                            "SSRF attack vector.",
                        )
                    else:
                        self.logger.display(f"  {method}: {status}")

                elif msg_type == MessageType.CALLERROR:
                    error_code = payload.get("error_code", "")
                    result_data["status"] = f"error:{error_code}"
                    self.logger.display(f"  {method}: {error_code}")

        except Exception as e:
            self.logger.debug(f"Diagnostics test failed: {e}")
            result_data["status"] = f"exception:{e}"

        self.results["data"]["diagnostics_test"] = result_data

    def test_remote_stop(self):
        """
        Test if an unauthorized RemoteStopTransaction command is accepted.

        Sends RemoteStopTransaction with a safe transaction ID (0) to test
        whether the charge point accepts stop commands without authorization.

        Safety: Uses SAFE_TRANSACTION_ID (0) which should not match any
        active transaction.
        """
        if not self.conn:
            return

        self.logger.display("[Security] RemoteStopTransaction test")
        version = self.results["data"].get("ocpp_version", "1.6") or "1.6"
        self.logger.debug(f"Security probe: RemoteStopTransaction (txId={SAFE_TRANSACTION_ID})")

        result_data = {"status": None, "transaction_id": SAFE_TRANSACTION_ID}

        try:
            msg = self._build_remote_stop_transaction(SAFE_TRANSACTION_ID, version=version)
            response = self.scanner._send_and_receive(self.conn, msg, timeout=5)

            if response is None:
                self.logger.display("  RemoteStopTransaction: no response")
                result_data["status"] = "no_response"
            else:
                msg_type, _, payload = self._parse_message(response)

                if msg_type == MessageType.CALLRESULT:
                    status = payload.get("status", "Unknown")
                    result_data["status"] = status
                    if status == "Accepted":
                        self.logger.warning(
                            "  RemoteStopTransaction: ACCEPTED "
                            "(unauthenticated session stop possible)"
                        )
                        self._add_finding(
                            "HIGH",
                            "Unauthorized RemoteStopTransaction accepted",
                            "RemoteStopTransaction was accepted without authentication. "
                            "Attacker can terminate active charging sessions.",
                        )
                    else:
                        self.logger.display(f"  RemoteStopTransaction: {status}")

                elif msg_type == MessageType.CALLERROR:
                    error_code = payload.get("error_code", "")
                    result_data["status"] = f"error:{error_code}"
                    self.logger.display(f"  RemoteStopTransaction: {error_code}")

        except Exception as e:
            self.logger.debug(f"RemoteStopTransaction failed: {e}")
            result_data["status"] = f"exception:{e}"

        self.results["data"]["remote_stop"] = result_data

    def test_reserve(self):
        """
        Test if unauthorized ReserveNow/CancelReservation commands are accepted.

        ReserveNow can be used for resource exhaustion -- reserving all
        connectors prevents legitimate users from charging.

        Safety: Uses SAFE_RESERVATION_ID and immediately cancels.
        """
        if not self.conn:
            return

        self.logger.display("[Security] ReserveNow/CancelReservation test")

        connector_id = getattr(self.args, "connector_id", 1) or 1
        version = self.results["data"].get("ocpp_version", "1.6") or "1.6"
        self.logger.debug(
            f"Security probe: ReserveNow (connector={connector_id}, reservation_id={SAFE_RESERVATION_ID})"
        )
        result_data = {"reserve_status": None, "cancel_status": None}

        # Step 1: ReserveNow
        try:
            msg = self._build_reserve_now(
                connector_id=connector_id,
                id_tag=FAKE_ID_TAG,
                reservation_id=SAFE_RESERVATION_ID,
                version=version,
            )
            response = self.scanner._send_and_receive(self.conn, msg, timeout=5)

            if response is None:
                self.logger.display("  ReserveNow: no response")
                result_data["reserve_status"] = "no_response"
            else:
                msg_type, _, payload = self._parse_message(response)

                if msg_type == MessageType.CALLRESULT:
                    status = payload.get("status", "Unknown")
                    result_data["reserve_status"] = status
                    if status == "Accepted":
                        self.logger.warning(
                            "  ReserveNow: ACCEPTED (unauthenticated reservation possible)"
                        )
                        self._add_finding(
                            "MEDIUM",
                            "Unauthorized ReserveNow accepted",
                            f"ReserveNow on connector {connector_id} was accepted. "
                            "Attacker can exhaust all connectors via reservations.",
                        )
                    else:
                        self.logger.display(f"  ReserveNow: {status}")

                elif msg_type == MessageType.CALLERROR:
                    error_code = payload.get("error_code", "")
                    result_data["reserve_status"] = f"error:{error_code}"
                    self.logger.display(f"  ReserveNow: {error_code}")

        except Exception as e:
            self.logger.debug(f"ReserveNow failed: {e}")
            result_data["reserve_status"] = f"exception:{e}"

        # Step 2: Always cancel (cleanup)
        try:
            cancel_msg = self._build_cancel_reservation(SAFE_RESERVATION_ID)
            response = self.scanner._send_and_receive(self.conn, cancel_msg, timeout=5)

            if response is not None:
                msg_type, _, payload = self._parse_message(response)
                if msg_type == MessageType.CALLRESULT:
                    result_data["cancel_status"] = payload.get("status", "Unknown")
                elif msg_type == MessageType.CALLERROR:
                    result_data["cancel_status"] = payload.get("error_code", "")
            else:
                result_data["cancel_status"] = "no_response"

            self.logger.debug(f"  CancelReservation: {result_data['cancel_status']}")

        except Exception as e:
            self.logger.debug(f"CancelReservation cleanup failed: {e}")
            result_data["cancel_status"] = f"exception:{e}"

        self.results["data"]["reservation_test"] = result_data

    def test_local_list(self):
        """
        Test GetLocalListVersion and SendLocalList access.

        GetLocalListVersion reveals the auth list version (info leak).
        SendLocalList tests if the auth list can be replaced without authorization.

        Safety: SendLocalList sends an empty list (no entries added/removed).
        """
        if not self.conn:
            return

        self.logger.display("[Security] LocalList access test")
        ocpp_ver = self.results["data"].get("ocpp_version", "1.6") or "1.6"
        self.logger.debug("Security probe: GetLocalListVersion + SendLocalList")

        result_data = {"list_version": None, "send_status": None}

        # Step 1: GetLocalListVersion
        try:
            msg = self._build_get_local_list_version()
            response = self.scanner._send_and_receive(self.conn, msg, timeout=5)

            if response is not None:
                msg_type, _, payload = self._parse_message(response)

                if msg_type == MessageType.CALLRESULT:
                    list_ver = payload.get("listVersion", -1)
                    result_data["list_version"] = list_ver
                    self.logger.display(f"  LocalList version: {list_ver}")

                    if list_ver >= 0:
                        self._add_finding(
                            "LOW",
                            "Local authorization list version disclosed",
                            f"GetLocalListVersion returned version {list_ver}. "
                            "Auth list metadata exposed.",
                        )

                elif msg_type == MessageType.CALLERROR:
                    error_code = payload.get("error_code", "")
                    self.logger.display(f"  GetLocalListVersion: {error_code}")

        except Exception as e:
            self.logger.debug(f"GetLocalListVersion failed: {e}")

        # Step 2: SendLocalList (empty, just testing access)
        try:
            msg = self._build_send_local_list(list_version=1, update_type="Full", version=ocpp_ver)
            response = self.scanner._send_and_receive(self.conn, msg, timeout=5)

            if response is None:
                result_data["send_status"] = "no_response"
            else:
                msg_type, _, payload = self._parse_message(response)

                if msg_type == MessageType.CALLRESULT:
                    status = payload.get("status", "Unknown")
                    result_data["send_status"] = status
                    if status == "Accepted":
                        self.logger.warning(
                            "  SendLocalList: ACCEPTED (unauthenticated auth list write possible)"
                        )
                        self._add_finding(
                            "CRITICAL",
                            "Unauthorized SendLocalList accepted",
                            "SendLocalList was accepted without authentication. "
                            "Attacker can replace the local authorization list, "
                            "granting or revoking charging access.",
                        )
                    else:
                        self.logger.display(f"  SendLocalList: {status}")

                elif msg_type == MessageType.CALLERROR:
                    error_code = payload.get("error_code", "")
                    result_data["send_status"] = f"error:{error_code}"
                    self.logger.display(f"  SendLocalList: {error_code}")

        except Exception as e:
            self.logger.debug(f"SendLocalList failed: {e}")
            result_data["send_status"] = f"exception:{e}"

        self.results["data"]["local_list_test"] = result_data

    # ==================================================================
    # Brute force credential testing
    # ==================================================================

    def _brute_force_http_auth(self, usernames, passwords):
        """
        Brute force HTTP Basic Auth credentials.

        Each attempt requires a new WebSocket connection because HTTP Basic Auth
        is sent in the WebSocket upgrade request headers.

        Args:
            usernames: List of usernames to test
            passwords: List of passwords to test
        """
        delay = getattr(self.args, "brute_rate", 0.5)
        continue_on_success = getattr(self.args, "continue_on_success", False)
        target_url = self.results["data"].get("target_url", "")

        credentials = [(u, p) for u in usernames for p in passwords]
        self.logger.debug(
            f"HTTP auth brute: {len(credentials)} pairs, delay={delay}s, "
            f"continue_on_success={continue_on_success}"
        )
        self.logger.display(
            f"[Brute] HTTP Basic Auth: {len(credentials)} pairs "
            f"({len(usernames)} users x {len(passwords)} passwords)"
        )

        valid_creds = []
        tested = 0

        for username, password in credentials:
            tested += 1
            try:
                # Build auth header
                cred_bytes = f"{username}:{password}".encode()
                auth_value = base64.b64encode(cred_bytes).decode()

                # Attempt WebSocket connection with these credentials
                conn = self.scanner._connect_with_auth(target_url, auth_value)

                if conn is not None:
                    self.logger.security_finding(
                        "Default credentials",
                        category=Category.AUTHENTICATION,
                        detail=f"Valid HTTP Basic Auth: {username}:{password}",
                    )
                    valid_creds.append({"username": username, "password": password})

                    # Clean up test connection
                    try:
                        self.scanner.disconnect(conn)
                    except Exception as e:
                        self.logger.debug(f"self.scanner.disconnect(conn): {e}")

                    if not continue_on_success:
                        break
                else:
                    self.logger.debug(f"[Brute] Failed: {username}:{password}")

            except Exception as e:
                self.logger.debug(f"[Brute] {username}:{password} -> {e}")

            if delay > 0:
                time.sleep(delay)

        self.logger.display(f"[Brute] Tested {tested} credentials, found {len(valid_creds)} valid")

        self.results["data"].setdefault("brute_force", {})["http_auth"] = {
            "tested": tested,
            "valid": valid_creds,
        }

        if valid_creds:
            cred_summary = ", ".join(f"{c['username']}:{c['password']}" for c in valid_creds[:3])
            self._add_finding(
                "CRITICAL",
                f"Valid HTTP Basic Auth credentials found ({len(valid_creds)})",
                f"Credentials: {cred_summary}",
            )

    def _brute_force_id_tags(self, id_tags):
        """
        Brute force OCPP IdTag authorization tokens.

        Uses the existing WebSocket connection to send Authorize CALL messages
        with different idTag values. No reconnection needed.

        Args:
            id_tags: List of idTag values to test
        """
        if not self.conn:
            self.logger.fail("[Brute] No connection for IdTag brute force")
            return

        delay = getattr(self.args, "brute_rate", 0.5)
        continue_on_success = getattr(self.args, "continue_on_success", False)

        version = self.results["data"].get("ocpp_version", "1.6") or "1.6"
        self.logger.debug(f"IdTag brute: {len(id_tags)} tokens, delay={delay}s")
        self.logger.display(f"[Brute] IdTag authorization: {len(id_tags)} tokens")

        valid_tags = []
        tested = 0

        for tag in id_tags:
            if not tag:
                continue
            tested += 1

            try:
                msg = self._build_authorize(tag, version=version)
                response = self.scanner._send_and_receive(self.conn, msg, timeout=5)

                if response:
                    msg_type, _, payload = self._parse_message(response)
                    if msg_type == MessageType.CALLRESULT:
                        # OCPP 1.6: idTagInfo.status, OCPP 2.0.1: idTokenInfo.status
                        status = (
                            payload.get("idTagInfo", {}).get("status")
                            or payload.get("idTokenInfo", {}).get("status")
                            or "Unknown"
                        )
                        if status == "Accepted":
                            self.logger.security_finding(
                                "Default credentials",
                                category=Category.AUTHENTICATION,
                                detail=f"Valid IdTag accepted: {tag}",
                            )
                            valid_tags.append({"id_tag": tag, "status": status})
                            if not continue_on_success:
                                break
                        else:
                            self.logger.debug(f"[Brute] {tag}: {status}")

            except Exception as e:
                self.logger.debug(f"[Brute] IdTag {tag}: {e}")

            if delay > 0:
                time.sleep(delay)

        self.logger.display(f"[Brute] Tested {tested} IdTags, found {len(valid_tags)} valid")

        self.results["data"].setdefault("brute_force", {})["id_tags"] = {
            "tested": tested,
            "valid": valid_tags,
        }

        if valid_tags:
            self._add_finding(
                "HIGH",
                f"Valid OCPP IdTag tokens found ({len(valid_tags)})",
                f"Tags: {', '.join(t['id_tag'] for t in valid_tags[:5])}",
            )

    # ==================================================================
    # Extended security probes (OCPP 2.0.1 features)
    # ==================================================================

    def _is_v201(self) -> bool:
        """Check if the detected OCPP version is 2.0.1 or later."""
        version = self.results["data"].get("ocpp_version", "1.6") or "1.6"
        return version.startswith("2.")

    def test_network_profile(self):
        """
        Test if SetNetworkProfile accepts an attacker-controlled CSMS URL (OCPP 2.0.1).

        Sends SetNetworkProfile with a safe non-routable URL (wss://0.0.0.0:443/ocpp/).
        If accepted, the charger can be redirected to a rogue CSMS -- a connection
        hijack attack.

        Safety: URL points to 0.0.0.0 which is non-routable.
        Requires: OCPP 2.0.1, --confirm
        """
        if not self.conn:
            return

        if not self._is_v201():
            self.logger.display("[Security] SetNetworkProfile: skipped (requires OCPP 2.0.1)")
            return

        self.logger.display("[Security] SetNetworkProfile redirect test (OCPP 2.0.1)")
        self.logger.debug(f"Security probe: SetNetworkProfile (url={FAKE_NETWORK_PROFILE_URL})")

        result_data = {"status": None, "url": FAKE_NETWORK_PROFILE_URL}

        try:
            msg = self._build_set_network_profile(
                configuration_slot=1,
                ocpp_csms_url=FAKE_NETWORK_PROFILE_URL,
                security_profile=1,
            )

            response = self.scanner._send_and_receive(self.conn, msg, timeout=5)
            if response is None:
                self.logger.display("  SetNetworkProfile: no response")
                result_data["status"] = "no_response"
            else:
                msg_type, _, payload = self._parse_message(response)

                if msg_type == MessageType.CALLRESULT:
                    status = payload.get("status", "Unknown")
                    result_data["status"] = status
                    if status == "Accepted":
                        self.logger.warning(
                            "  SetNetworkProfile: ACCEPTED (connection hijack possible!)"
                        )
                        self._add_finding(
                            "CRITICAL",
                            "SetNetworkProfile accepted attacker-controlled CSMS URL",
                            f"SetNetworkProfile with URL '{FAKE_NETWORK_PROFILE_URL}' "
                            "was accepted. Charger can be redirected to a rogue CSMS.",
                        )
                    else:
                        self.logger.display(f"  SetNetworkProfile: {status}")

                elif msg_type == MessageType.CALLERROR:
                    error_code = payload.get("error_code", "")
                    result_data["status"] = f"error:{error_code}"
                    self.logger.display(f"  SetNetworkProfile: {error_code}")

        except Exception as e:
            self.logger.debug(f"SetNetworkProfile failed: {e}")
            result_data["status"] = f"exception:{e}"

        self.results["data"]["network_profile_test"] = result_data

    def test_install_certificate(self):
        """
        Test if InstallCertificate accepts an arbitrary root CA (OCPP 2.0.1).

        Sends InstallCertificate with a fake test certificate PEM. If accepted,
        a rogue CA can be installed on the charger, enabling MITM attacks.

        If accepted, immediately attempts DeleteCertificate to clean up.

        Safety: Uses clearly fake PEM that is not a valid X.509 certificate.
        Requires: OCPP 2.0.1, --confirm
        """
        if not self.conn:
            return

        if not self._is_v201():
            self.logger.display("[Security] InstallCertificate: skipped (requires OCPP 2.0.1)")
            return

        self.logger.display("[Security] InstallCertificate root CA test (OCPP 2.0.1)")
        self.logger.debug("Security probe: InstallCertificate (CSMSRootCertificate)")

        result_data = {"install_status": None, "cleanup_status": None}

        try:
            msg = self._build_install_certificate(
                certificate_type="CSMSRootCertificate",
                certificate_pem=PROBE_TEST_CERTIFICATE,
            )

            response = self.scanner._send_and_receive(self.conn, msg, timeout=5)
            if response is None:
                self.logger.display("  InstallCertificate: no response")
                result_data["install_status"] = "no_response"
            else:
                msg_type, _, payload = self._parse_message(response)

                if msg_type == MessageType.CALLRESULT:
                    status = payload.get("status", "Unknown")
                    result_data["install_status"] = status
                    if status == "Accepted":
                        self.logger.warning(
                            "  InstallCertificate: ACCEPTED (rogue root CA installable!)"
                        )
                        self._add_finding(
                            "CRITICAL",
                            "InstallCertificate accepted arbitrary root CA",
                            "InstallCertificate with a fake CSMSRootCertificate was "
                            "accepted. Attacker can install rogue CA for MITM attacks.",
                        )
                        # Attempt cleanup via DeleteCertificate
                        result_data["cleanup_status"] = self._cleanup_installed_cert()
                    else:
                        self.logger.display(f"  InstallCertificate: {status}")

                elif msg_type == MessageType.CALLERROR:
                    error_code = payload.get("error_code", "")
                    result_data["install_status"] = f"error:{error_code}"
                    self.logger.display(f"  InstallCertificate: {error_code}")

        except Exception as e:
            self.logger.debug(f"InstallCertificate failed: {e}")
            result_data["install_status"] = f"exception:{e}"

        self.results["data"]["install_cert_test"] = result_data

    def _cleanup_installed_cert(self):
        """
        Attempt to delete the probe certificate via DeleteCertificate.

        Returns:
            Status string of the cleanup attempt
        """
        self.logger.debug("Attempting DeleteCertificate cleanup for probe cert")
        try:
            cleanup_msg = self._build_delete_certificate(
                hash_algorithm="SHA256",
                issuer_name_hash="OIDA-PROBE",
                issuer_key_hash="OIDA-PROBE",
                serial_number="0",
            )
            response = self.scanner._send_and_receive(self.conn, cleanup_msg, timeout=5)

            if response is not None:
                msg_type, _, payload = self._parse_message(response)
                if msg_type == MessageType.CALLRESULT:
                    status = payload.get("status", "Unknown")
                    self.logger.debug(f"DeleteCertificate cleanup: {status}")
                    return status
                elif msg_type == MessageType.CALLERROR:
                    error_code = payload.get("error_code", "")
                    self.logger.debug(f"DeleteCertificate cleanup error: {error_code}")
                    return f"error:{error_code}"
            return "no_response"

        except Exception as e:
            self.logger.debug(f"DeleteCertificate cleanup failed: {e}")
            return f"exception:{e}"

    def test_display_message(self):
        """
        Test if SetDisplayMessage accepts arbitrary messages (OCPP 2.0.1).

        Sends SetDisplayMessage with a benign security audit message. If
        accepted, an attacker can display arbitrary messages on the charger
        screen -- a social engineering vector.

        If accepted, immediately attempts ClearDisplayMessage to clean up.

        Requires: OCPP 2.0.1, --confirm
        """
        if not self.conn:
            return

        if not self._is_v201():
            self.logger.display("[Security] SetDisplayMessage: skipped (requires OCPP 2.0.1)")
            return

        self.logger.display("[Security] SetDisplayMessage test (OCPP 2.0.1)")
        self.logger.debug(f"Security probe: SetDisplayMessage (text={PROBE_DISPLAY_MESSAGE!r})")

        message_id = 99999
        result_data = {"set_status": None, "clear_status": None}

        try:
            msg = self._build_set_display_message(
                message_id=message_id,
                message_text=PROBE_DISPLAY_MESSAGE,
                priority="NormalCycle",
            )

            response = self.scanner._send_and_receive(self.conn, msg, timeout=5)
            if response is None:
                self.logger.display("  SetDisplayMessage: no response")
                result_data["set_status"] = "no_response"
            else:
                msg_type, _, payload = self._parse_message(response)

                if msg_type == MessageType.CALLRESULT:
                    status = payload.get("status", "Unknown")
                    result_data["set_status"] = status
                    if status == "Accepted":
                        self.logger.warning(
                            "  SetDisplayMessage: ACCEPTED (social engineering vector)"
                        )
                        self._add_finding(
                            "MEDIUM",
                            "SetDisplayMessage accepted without authorization",
                            f"SetDisplayMessage with text '{PROBE_DISPLAY_MESSAGE}' was "
                            "accepted. Attacker can display arbitrary messages on screen.",
                        )
                        # Cleanup
                        result_data["clear_status"] = self._cleanup_display_message(message_id)
                    else:
                        self.logger.display(f"  SetDisplayMessage: {status}")

                elif msg_type == MessageType.CALLERROR:
                    error_code = payload.get("error_code", "")
                    result_data["set_status"] = f"error:{error_code}"
                    self.logger.display(f"  SetDisplayMessage: {error_code}")

        except Exception as e:
            self.logger.debug(f"SetDisplayMessage failed: {e}")
            result_data["set_status"] = f"exception:{e}"

        self.results["data"]["display_message_test"] = result_data

    def _cleanup_display_message(self, message_id):
        """
        Attempt to clear the probe display message via ClearDisplayMessage.

        Args:
            message_id: ID of the message to clear

        Returns:
            Status string of the cleanup attempt
        """
        self.logger.debug(f"Attempting ClearDisplayMessage cleanup (id={message_id})")
        try:
            cleanup_msg = self._build_clear_display_message(message_id=message_id)
            response = self.scanner._send_and_receive(self.conn, cleanup_msg, timeout=5)

            if response is not None:
                msg_type, _, payload = self._parse_message(response)
                if msg_type == MessageType.CALLRESULT:
                    status = payload.get("status", "Unknown")
                    self.logger.debug(f"ClearDisplayMessage cleanup: {status}")
                    return status
                elif msg_type == MessageType.CALLERROR:
                    error_code = payload.get("error_code", "")
                    self.logger.debug(f"ClearDisplayMessage cleanup error: {error_code}")
                    return f"error:{error_code}"
            return "no_response"

        except Exception as e:
            self.logger.debug(f"ClearDisplayMessage cleanup failed: {e}")
            return f"exception:{e}"

    def test_customer_info(self):
        """
        Test if CustomerInformation allows PII exfiltration (OCPP 2.0.1).

        Sends CustomerInformation with report=True to request customer data.
        If accepted, customer personally identifiable information (PII) may
        be exfiltrated from the charging station.

        Safety: Uses FAKE_ID_TAG, clear=False (no data deletion).
        Requires: OCPP 2.0.1, --confirm
        """
        if not self.conn:
            return

        if not self._is_v201():
            self.logger.display("[Security] CustomerInformation: skipped (requires OCPP 2.0.1)")
            return

        self.logger.display("[Security] CustomerInformation PII access test (OCPP 2.0.1)")
        self.logger.debug(
            f"Security probe: CustomerInformation (report=True, idToken={FAKE_ID_TAG})"
        )

        result_data = {"status": None}

        try:
            msg = self._build_get_customer_information(
                request_id=1,
                report=True,
                clear=False,
                id_token=FAKE_ID_TAG,
            )

            response = self.scanner._send_and_receive(self.conn, msg, timeout=5)
            if response is None:
                self.logger.display("  CustomerInformation: no response")
                result_data["status"] = "no_response"
            else:
                msg_type, _, payload = self._parse_message(response)

                if msg_type == MessageType.CALLRESULT:
                    status = payload.get("status", "Unknown")
                    result_data["status"] = status
                    if status == "Accepted":
                        self.logger.warning(
                            "  CustomerInformation: ACCEPTED (PII exfiltration possible)"
                        )
                        self._add_finding(
                            "HIGH",
                            "CustomerInformation accepted without authorization",
                            "CustomerInformation with report=True was accepted. "
                            "Customer PII data may be exfiltrated from the charger.",
                        )
                    else:
                        self.logger.display(f"  CustomerInformation: {status}")

                elif msg_type == MessageType.CALLERROR:
                    error_code = payload.get("error_code", "")
                    result_data["status"] = f"error:{error_code}"
                    self.logger.display(f"  CustomerInformation: {error_code}")

        except Exception as e:
            self.logger.debug(f"CustomerInformation failed: {e}")
            result_data["status"] = f"exception:{e}"

        self.results["data"]["customer_info_test"] = result_data

    def test_ssrf_extended(self):
        """
        Test extended SSRF payloads via UpdateFirmware and GetDiagnostics/GetLog.

        Tests multiple SSRF vectors including cloud provider metadata endpoints
        (AWS, Azure, GCP), localhost, and file:// URIs. For each URL, sends
        UpdateFirmware to check if the charger accepts attacker-controlled URLs.

        Reports CRITICAL for cloud metadata URLs, HIGH for localhost/file URLs.
        Requires: --confirm
        """
        if not self.conn:
            return

        self.logger.display("[Security] Extended SSRF probe")
        version = self.results["data"].get("ocpp_version", "1.6") or "1.6"
        self.logger.debug(
            f"Security probe: extended SSRF ({len(SSRF_PROBE_URLS)} URLs, version={version})"
        )

        result_data = {"probes": []}

        for url, label, severity in SSRF_PROBE_URLS:
            probe_result = {"url": url, "label": label, "severity": severity, "status": None}

            try:
                # Use UpdateFirmware as the SSRF vector (works on both 1.6 and 2.0.1)
                fw_msg = self._build_update_firmware(
                    location=url,
                    retrieve_date=FAKE_FIRMWARE_RETRIEVE_DATE,
                    retries=0,
                    version=version,
                )

                response = self.scanner._send_and_receive(self.conn, fw_msg, timeout=5)
                if response is None:
                    probe_result["status"] = "no_response"
                    self.logger.display(f"  SSRF [{label}]: no response")
                else:
                    msg_type, _, payload = self._parse_message(response)

                    if msg_type == MessageType.CALLRESULT:
                        # UpdateFirmware returns {} on accept (1.6) or
                        # {"status": "Accepted"} on 2.0.1
                        probe_result["status"] = "Accepted"
                        self.logger.warning(f"  SSRF [{label}]: ACCEPTED ({url})")
                        self._add_finding(
                            severity,
                            f"SSRF via UpdateFirmware: {label} URL accepted",
                            f"UpdateFirmware with URL '{url}' was accepted. "
                            f"Charger will attempt to fetch from {label} endpoint.",
                        )

                    elif msg_type == MessageType.CALLERROR:
                        error_code = payload.get("error_code", "")
                        probe_result["status"] = f"error:{error_code}"
                        self.logger.display(f"  SSRF [{label}]: {error_code}")

            except Exception as e:
                self.logger.debug(f"SSRF probe [{label}] failed: {e}")
                probe_result["status"] = f"exception:{e}"

            result_data["probes"].append(probe_result)

        # Also test via GetDiagnostics/GetLog for the cloud metadata URLs
        for url, label, severity in SSRF_PROBE_URLS[:3]:
            diag_result = {
                "url": url,
                "label": f"{label} (diag)",
                "severity": severity,
                "status": None,
            }

            try:
                if version.startswith("2."):
                    diag_msg = self._build_get_log(
                        log_type="DiagnosticsLog",
                        request_id=1,
                        location=url,
                    )
                else:
                    diag_msg = self._build_get_diagnostics(location=url)

                method = "GetLog" if version.startswith("2.") else "GetDiagnostics"

                response = self.scanner._send_and_receive(self.conn, diag_msg, timeout=5)
                if response is None:
                    diag_result["status"] = "no_response"
                else:
                    msg_type, _, payload = self._parse_message(response)

                    if msg_type == MessageType.CALLRESULT:
                        # Same GetDiagnostics.conf caveat as test_diagnostics():
                        # fileName is optional in OCPP 1.6, so an empty {}
                        # CALLRESULT means the CP is not going to upload
                        # anything and must not be flagged as SSRF.
                        accepted = version.startswith("2.") or bool(payload.get("fileName"))
                        diag_result["status"] = "Accepted" if accepted else "AcceptedNoUpload"
                        if accepted:
                            self.logger.warning(f"  SSRF [{label}] via {method}: ACCEPTED")
                            self._add_finding(
                                severity,
                                f"SSRF via {method}: {label} URL accepted",
                                f"{method} with URL '{url}' was accepted. "
                                f"Charger will upload data to {label} endpoint.",
                            )

                    elif msg_type == MessageType.CALLERROR:
                        error_code = payload.get("error_code", "")
                        diag_result["status"] = f"error:{error_code}"

            except Exception as e:
                self.logger.debug(f"SSRF diag probe [{label}] failed: {e}")
                diag_result["status"] = f"exception:{e}"

            result_data["probes"].append(diag_result)

        self.results["data"]["ssrf_extended"] = result_data

    def test_ws_hijacking(self):
        """
        Test WebSocket connection hijacking (SaiFlow-style attack).

        Opens a second WebSocket connection to the same charger ID while the
        first connection is still active. Checks for three outcomes:

        1. Both connections alive (parallel) -> CRITICAL (data leak / injection)
        2. Second accepted, first displaced -> HIGH (displacement DoS)
        3. Second connection rejected -> GOOD (proper handling)

        After the second connection test, verifies if the first connection
        is still alive by sending a Heartbeat.

        Requires: --confirm
        """
        if not self.conn:
            return

        self.logger.display("[Security] WebSocket connection hijacking test (SaiFlow)")

        target_url = self.results["data"].get("target_url", "")
        self.logger.debug(f"Security probe: WS hijacking test (url={target_url})")

        result_data = {
            "accepted": False,
            "first_displaced": False,
            "parallel": False,
            "error": None,
        }

        try:
            # Run the hijacking test via the scanner
            hijack_result = self.scanner.test_ws_hijacking(target_url)
            result_data.update(hijack_result)

            if not hijack_result.get("accepted"):
                error = hijack_result.get("error", "")
                self.logger.display(
                    f"  Second connection rejected ({error}) -- good, proper handling"
                )
            else:
                # Second connection was accepted -- check if first is still alive
                self.logger.debug("Second connection accepted, checking first connection liveness")
                first_alive = self._check_first_connection_alive()

                if first_alive and hijack_result.get("parallel"):
                    result_data["parallel"] = True
                    result_data["first_displaced"] = False
                    self.logger.warning(
                        "  PARALLEL connections accepted (SaiFlow data theft vector!)"
                    )
                    self._add_finding(
                        "CRITICAL",
                        "WebSocket parallel connection hijacking (SaiFlow)",
                        "A second WebSocket connection was accepted while the first "
                        "remained active. Attacker can intercept/inject OCPP messages "
                        "in parallel (CVE-2023-29857 style attack).",
                    )
                elif not first_alive:
                    result_data["first_displaced"] = True
                    result_data["parallel"] = False
                    self.logger.warning(
                        "  First connection DISPLACED by second (SaiFlow DoS vector)"
                    )
                    self._add_finding(
                        "HIGH",
                        "WebSocket connection displacement (SaiFlow DoS)",
                        "A second WebSocket connection was accepted and the first "
                        "connection was dropped. Attacker can perform displacement "
                        "denial-of-service attacks.",
                    )
                else:
                    # Second accepted but no clear parallel behavior
                    self.logger.display("  Second connection accepted (behavior unclear)")

        except Exception as e:
            self.logger.debug(f"WS hijacking test failed: {e}")
            result_data["error"] = str(e)

        self.results["data"]["ws_hijacking"] = result_data

    def _check_first_connection_alive(self) -> bool:
        """
        Check if the primary WebSocket connection is still alive.

        Sends a Heartbeat and checks for a response.

        Returns:
            True if connection is still alive, False otherwise
        """
        if not self.conn:
            return False

        try:
            hb_msg = self._build_heartbeat()
            response = self.scanner._send_and_receive(self.conn, hb_msg, timeout=3)
            if response is not None:
                self.logger.debug("First connection still alive (Heartbeat OK)")
                return True
            self.logger.debug("First connection: Heartbeat got no response")
            return False
        except Exception as e:
            self.logger.debug(f"First connection liveness check failed: {e}")
            return False
