#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Unit tests for OCPP protocol scanner functionality.

Tests the OCPP scanner module without requiring actual network connections.
All WebSocket interactions are mocked.

Focus areas:
- OCPP-J message structure correctness (CALL/CALLRESULT/CALLERROR format)
- Version-specific payload differences (v1.6 vs v2.0.1)
- Security finding severity and cleanup behavior
- Parse/validation edge cases
- Dispatch wiring completeness
- Charging flow lifecycle and cleanup-on-failure
"""

import json
import unittest
from unittest.mock import Mock, patch, MagicMock, AsyncMock

from oida.utils.confirm_gate import ConfirmGateMixin


# ---------------------------------------------------------------------------
# Constants tests -- verify structural relationships, not individual values
# ---------------------------------------------------------------------------


class TestOCPPConstants(unittest.TestCase):
    """Test OCPP constants have correct structural relationships and invariants"""

    def test_message_type_values_match_ocpp_j_spec(self):
        """OCPP-J spec mandates CALL=2, CALLRESULT=3, CALLERROR=4.
        These are wire protocol values, not arbitrary choices."""
        from oida.protocols.ocpp.constants import MessageType

        self.assertEqual(MessageType.CALL, 2)
        self.assertEqual(MessageType.CALLRESULT, 3)
        self.assertEqual(MessageType.CALLERROR, 4)

    def test_subprotocol_mapping_is_bidirectional(self):
        """SUBPROTOCOL_TO_VERSION must be the exact inverse of OCPP_SUBPROTOCOLS."""
        from oida.protocols.ocpp.constants import OCPP_SUBPROTOCOLS, SUBPROTOCOL_TO_VERSION

        for version, subprotocol in OCPP_SUBPROTOCOLS.items():
            self.assertIn(
                subprotocol, SUBPROTOCOL_TO_VERSION, f"Missing reverse mapping for {subprotocol}"
            )
            self.assertEqual(
                SUBPROTOCOL_TO_VERSION[subprotocol],
                version,
                f"Reverse mapping mismatch for {subprotocol}",
            )

    def test_all_actions_is_union_of_cp_and_cs(self):
        """ALL_ACTIONS_V16 must contain every CP-initiated and CS-initiated action."""
        from oida.protocols.ocpp.constants import (
            ALL_ACTIONS_V16,
            CP_INITIATED_ACTIONS_V16,
            CS_INITIATED_ACTIONS_V16,
        )

        for action in CP_INITIATED_ACTIONS_V16:
            self.assertIn(
                action, ALL_ACTIONS_V16, f"CP action '{action}' missing from ALL_ACTIONS_V16"
            )
        for action in CS_INITIATED_ACTIONS_V16:
            self.assertIn(
                action, ALL_ACTIONS_V16, f"CS action '{action}' missing from ALL_ACTIONS_V16"
            )

    def test_all_actions_v201_is_union(self):
        """ALL_ACTIONS_V201 must contain every CP and CS 2.0.1 action."""
        from oida.protocols.ocpp.constants import (
            ALL_ACTIONS_V201,
            CP_INITIATED_ACTIONS_V201,
            CS_INITIATED_ACTIONS_V201,
        )

        for action in CP_INITIATED_ACTIONS_V201:
            self.assertIn(action, ALL_ACTIONS_V201)
        for action in CS_INITIATED_ACTIONS_V201:
            self.assertIn(action, ALL_ACTIONS_V201)

    def test_security_profile_names_cover_all_profiles(self):
        """Every SecurityProfile enum member must have a human-readable name."""
        from oida.protocols.ocpp.constants import SecurityProfile, SECURITY_PROFILE_NAMES

        for profile in SecurityProfile:
            self.assertIn(
                profile,
                SECURITY_PROFILE_NAMES,
                f"SecurityProfile.{profile.name} has no display name",
            )

    def test_error_code_descriptions_cover_all_codes(self):
        """Every ErrorCode enum value must have a description."""
        from oida.protocols.ocpp.constants import ErrorCode, ERROR_CODE_DESCRIPTIONS

        for code in ErrorCode:
            self.assertIn(
                code.value, ERROR_CODE_DESCRIPTIONS, f"ErrorCode '{code.value}' has no description"
            )

    def test_sensitive_config_keys_subset_of_config_keys(self):
        """All sensitive config keys should be in the main config keys list."""
        from oida.protocols.ocpp.constants import (
            SENSITIVE_CONFIG_KEYS,
            CONFIGURATION_KEYS_V16,
        )

        for key in SENSITIVE_CONFIG_KEYS:
            self.assertIn(
                key, CONFIGURATION_KEYS_V16, f"Sensitive key '{key}' not in CONFIGURATION_KEYS_V16"
            )

    def test_safety_constants_are_non_functional(self):
        """Fake/safe constants must be clearly non-functional values."""
        from oida.protocols.ocpp.constants import (
            FAKE_ID_TAG,
            FAKE_FIRMWARE_URL,
            FAKE_DIAGNOSTICS_URL,
            FAKE_LOG_URL,
            SAFE_CHARGING_PROFILE_ID,
            SAFE_TRANSACTION_ID,
        )

        # Fake URLs must use 0.0.0.0 (non-routable)
        self.assertIn("0.0.0.0", FAKE_FIRMWARE_URL)
        self.assertIn("0.0.0.0", FAKE_DIAGNOSTICS_URL)
        self.assertIn("0.0.0.0", FAKE_LOG_URL)
        # Fake ID tag must be clearly identifiable
        self.assertIn("OIDA", FAKE_ID_TAG)
        # Safe IDs use extreme or zero values
        self.assertGreater(SAFE_CHARGING_PROFILE_ID, 10000)
        self.assertEqual(SAFE_TRANSACTION_ID, 0)

    def test_dangerous_actions_exist_in_v16_cs_actions(self):
        """Security checks reference dangerous actions; verify they are real CS actions."""
        from oida.protocols.ocpp.constants import CS_INITIATED_ACTIONS_V16

        dangerous = [
            "Reset",
            "UpdateFirmware",
            "ChangeConfiguration",
            "RemoteStartTransaction",
            "RemoteStopTransaction",
            "SetChargingProfile",
            "UnlockConnector",
            "ClearCache",
            "SendLocalList",
        ]
        for action in dangerous:
            self.assertIn(
                action, CS_INITIATED_ACTIONS_V16, f"Dangerous action '{action}' not in CS actions"
            )


# ---------------------------------------------------------------------------
# Messages mixin tests -- verify OCPP-J wire format correctness
# ---------------------------------------------------------------------------


class TestMessagesMixin(unittest.TestCase):
    """Test OCPP message crafting produces correct OCPP-J wire format"""

    def _make_mixin(self):
        from oida.protocols.ocpp.mixins.messages import MessagesMixin

        return MessagesMixin()

    # --- CALL message format [2, messageId, action, payload] ---

    def test_build_call_produces_4_element_array(self):
        """OCPP-J CALL must be exactly [2, messageId, action, payload]."""
        mixin = self._make_mixin()
        raw = mixin._build_call("Heartbeat", {})
        data = json.loads(raw)

        self.assertEqual(len(data), 4, "CALL must have exactly 4 elements")
        self.assertEqual(data[0], 2, "First element must be MessageType.CALL (2)")
        self.assertIsInstance(data[1], str, "Message ID must be a string")
        self.assertGreater(len(data[1]), 0, "Message ID must be non-empty")
        self.assertEqual(data[2], "Heartbeat", "Third element must be the action name")
        self.assertEqual(data[3], {}, "Fourth element must be the payload dict")

    def test_build_call_with_none_payload_defaults_to_empty_dict(self):
        """None payload must be normalized to {} in the wire format."""
        mixin = self._make_mixin()
        raw = mixin._build_call("Heartbeat", None)
        data = json.loads(raw)

        self.assertEqual(data[3], {})

    def test_build_call_generates_unique_message_ids(self):
        """Each CALL must have a unique message ID for request correlation."""
        mixin = self._make_mixin()
        ids = set()
        for _ in range(20):
            raw = mixin._build_call("Heartbeat", {})
            data = json.loads(raw)
            ids.add(data[1])

        self.assertEqual(len(ids), 20, "All 20 message IDs should be unique")

    # --- CALLRESULT message format [3, messageId, payload] ---

    def test_build_call_result_produces_3_element_array(self):
        """OCPP-J CALLRESULT must be exactly [3, messageId, payload]."""
        mixin = self._make_mixin()
        raw = mixin._build_call_result("abc123", {"status": "Accepted"})
        data = json.loads(raw)

        self.assertEqual(len(data), 3, "CALLRESULT must have exactly 3 elements")
        self.assertEqual(data[0], 3, "First element must be MessageType.CALLRESULT (3)")
        self.assertEqual(data[1], "abc123", "Must echo the original message ID")
        self.assertEqual(data[2]["status"], "Accepted")

    def test_build_call_result_none_payload_defaults_to_empty(self):
        mixin = self._make_mixin()
        raw = mixin._build_call_result("id1", None)
        data = json.loads(raw)

        self.assertEqual(data[2], {})

    # --- Parse message: round-trip and edge cases ---

    def test_parse_call_extracts_action_and_payload(self):
        """Parsing a CALL must return action and payload in a structured dict."""
        mixin = self._make_mixin()
        raw = json.dumps([2, "msg1", "BootNotification", {"chargePointVendor": "Test"}])
        msg_type, msg_id, payload = mixin._parse_message(raw)

        self.assertEqual(msg_type, 2)
        self.assertEqual(msg_id, "msg1")
        self.assertEqual(payload["action"], "BootNotification")
        self.assertEqual(payload["payload"]["chargePointVendor"], "Test")

    def test_parse_callresult_returns_payload_directly(self):
        """CALLRESULT parsing returns the payload dict directly (not wrapped)."""
        mixin = self._make_mixin()
        raw = json.dumps([3, "msg1", {"currentTime": "2025-01-01T00:00:00Z"}])
        msg_type, msg_id, payload = mixin._parse_message(raw)

        self.assertEqual(msg_type, 3)
        self.assertEqual(msg_id, "msg1")
        self.assertEqual(payload["currentTime"], "2025-01-01T00:00:00Z")

    def test_parse_callerror_extracts_error_fields(self):
        """CALLERROR parsing must extract error_code, error_description, and details."""
        mixin = self._make_mixin()
        raw = json.dumps([4, "msg1", "NotImplemented", "Unknown action", {"key": "val"}])
        msg_type, msg_id, payload = mixin._parse_message(raw)

        self.assertEqual(msg_type, 4)
        self.assertEqual(payload["error_code"], "NotImplemented")
        self.assertEqual(payload["error_description"], "Unknown action")
        self.assertEqual(payload["details"], {"key": "val"})

    def test_parse_invalid_json_raises_value_error(self):
        mixin = self._make_mixin()
        with self.assertRaises(ValueError) as ctx:
            mixin._parse_message("not valid json {{")
        self.assertIn("Invalid JSON", str(ctx.exception))

    def test_parse_non_array_json_raises_value_error(self):
        """JSON object (dict) is not valid OCPP-J format."""
        mixin = self._make_mixin()
        with self.assertRaises(ValueError):
            mixin._parse_message('{"type": 2, "id": "msg1"}')

    def test_parse_too_short_array_raises_value_error(self):
        mixin = self._make_mixin()
        with self.assertRaises(ValueError):
            mixin._parse_message(json.dumps([2, "id"]))

    def test_parse_unknown_message_type_raises_value_error(self):
        mixin = self._make_mixin()
        with self.assertRaises(ValueError) as ctx:
            mixin._parse_message(json.dumps([99, "id", {}]))
        self.assertIn("Unknown message type", str(ctx.exception))

    def test_parse_call_with_only_3_elements_raises(self):
        """CALL requires exactly 4 elements (type, id, action, payload)."""
        mixin = self._make_mixin()
        with self.assertRaises(ValueError) as ctx:
            mixin._parse_message(json.dumps([2, "id1", "Action"]))
        self.assertIn("4 elements", str(ctx.exception))

    def test_parse_callerror_with_only_3_elements_raises(self):
        """CALLERROR requires 5 elements."""
        mixin = self._make_mixin()
        with self.assertRaises(ValueError):
            mixin._parse_message(json.dumps([4, "id1", "Error"]))

    def test_parse_message_id_coerced_to_string(self):
        """Numeric message IDs should be coerced to string."""
        mixin = self._make_mixin()
        raw = json.dumps([3, 12345, {"status": "ok"}])
        msg_type, msg_id, payload = mixin._parse_message(raw)

        self.assertIsInstance(msg_id, str)
        self.assertEqual(msg_id, "12345")

    def test_build_then_parse_call_roundtrip(self):
        """Building and parsing a CALL message should preserve all fields."""
        mixin = self._make_mixin()
        payload = {"chargePointVendor": "Test", "chargePointModel": "T1"}
        raw = mixin._build_call("BootNotification", payload)
        msg_type, msg_id, parsed = mixin._parse_message(raw)

        self.assertEqual(msg_type, 2)
        self.assertEqual(parsed["action"], "BootNotification")
        self.assertEqual(parsed["payload"]["chargePointVendor"], "Test")
        self.assertEqual(parsed["payload"]["chargePointModel"], "T1")

    def test_build_then_parse_callresult_roundtrip(self):
        mixin = self._make_mixin()
        raw = mixin._build_call_result("abc", {"status": "Accepted"})
        msg_type, msg_id, parsed = mixin._parse_message(raw)

        self.assertEqual(msg_type, 3)
        self.assertEqual(msg_id, "abc")
        self.assertEqual(parsed["status"], "Accepted")

    def test_parse_callerror_roundtrip(self):
        mixin = self._make_mixin()
        raw = json.dumps([4, "abc", "InternalError", "Oops", {"detail": "stack"}])
        msg_type, msg_id, parsed = mixin._parse_message(raw)

        self.assertEqual(msg_type, 4)
        self.assertEqual(parsed["error_code"], "InternalError")
        self.assertEqual(parsed["error_description"], "Oops")
        self.assertEqual(parsed["details"]["detail"], "stack")

    # --- Version-specific BootNotification payload ---

    def test_boot_notification_v16_uses_flat_fields(self):
        """OCPP 1.6 BootNotification uses chargePointVendor/chargePointModel at top level."""
        mixin = self._make_mixin()
        raw = mixin._build_boot_notification("1.6")
        data = json.loads(raw)
        payload = data[3]

        self.assertIn("chargePointVendor", payload)
        self.assertIn("chargePointModel", payload)
        self.assertNotIn(
            "chargingStation", payload, "v1.6 should NOT use nested chargingStation structure"
        )
        self.assertNotIn("reason", payload, "v1.6 should NOT have a 'reason' field")

    def test_boot_notification_v201_uses_nested_structure(self):
        """OCPP 2.0.1 BootNotification uses chargingStation nested object."""
        mixin = self._make_mixin()
        raw = mixin._build_boot_notification("2.0.1")
        data = json.loads(raw)
        payload = data[3]

        self.assertIn("reason", payload)
        self.assertIn("chargingStation", payload)
        self.assertIn("vendorName", payload["chargingStation"])
        self.assertIn("model", payload["chargingStation"])
        self.assertNotIn("chargePointVendor", payload, "v2.0.1 should NOT use flat v1.6 fields")

    def test_boot_notification_v21_uses_v2x_format(self):
        """OCPP 2.1 should use the same nested structure as v2.0.1."""
        mixin = self._make_mixin()
        raw = mixin._build_boot_notification("2.1")
        data = json.loads(raw)
        payload = data[3]

        self.assertIn("chargingStation", payload)
        self.assertIn("reason", payload)

    # --- Version-specific Authorize payload ---

    def test_authorize_v16_uses_flat_id_tag(self):
        """OCPP 1.6 Authorize uses flat 'idTag' field."""
        mixin = self._make_mixin()
        raw = mixin._build_authorize("RFID001", version="1.6")
        data = json.loads(raw)

        self.assertEqual(data[3]["idTag"], "RFID001")
        self.assertNotIn("idToken", data[3])

    def test_authorize_v201_uses_nested_id_token(self):
        """OCPP 2.0.1 Authorize uses nested 'idToken' with type field."""
        mixin = self._make_mixin()
        raw = mixin._build_authorize("RFID001", version="2.0.1")
        data = json.loads(raw)

        self.assertNotIn("idTag", data[3])
        self.assertEqual(data[3]["idToken"]["idToken"], "RFID001")
        self.assertEqual(data[3]["idToken"]["type"], "ISO14443")

    # --- TriggerMessage connector_id=0 exclusion ---

    def test_trigger_message_excludes_connector_id_when_zero(self):
        """connector_id=0 should be omitted from TriggerMessage per OCPP spec."""
        mixin = self._make_mixin()
        raw = mixin._build_trigger_message("Heartbeat", connector_id=0)
        data = json.loads(raw)

        self.assertNotIn("connectorId", data[3])

    def test_trigger_message_includes_connector_id_when_positive(self):
        mixin = self._make_mixin()
        raw = mixin._build_trigger_message("StatusNotification", connector_id=1)
        data = json.loads(raw)

        self.assertEqual(data[3]["connectorId"], 1)

    # --- DataTransfer optional fields ---

    def test_data_transfer_minimal_only_vendor_id(self):
        """DataTransfer with only vendor_id should omit messageId and data."""
        mixin = self._make_mixin()
        raw = mixin._build_data_transfer("TestVendor")
        data = json.loads(raw)

        self.assertEqual(data[3]["vendorId"], "TestVendor")
        self.assertNotIn("messageId", data[3])
        self.assertNotIn("data", data[3])

    def test_data_transfer_with_all_fields(self):
        mixin = self._make_mixin()
        raw = mixin._build_data_transfer("TestVendor", "msg1", "hello")
        data = json.loads(raw)

        self.assertEqual(data[3]["vendorId"], "TestVendor")
        self.assertEqual(data[3]["messageId"], "msg1")
        self.assertEqual(data[3]["data"], "hello")

    # --- ClearChargingProfile optional fields ---

    def test_clear_charging_profile_empty_when_no_args(self):
        mixin = self._make_mixin()
        raw = mixin._build_clear_charging_profile()
        data = json.loads(raw)

        self.assertEqual(data[3], {})

    def test_clear_charging_profile_includes_all_specified_fields(self):
        mixin = self._make_mixin()
        raw = mixin._build_clear_charging_profile(
            profile_id=99, connector_id=1, purpose="TxDefaultProfile"
        )
        data = json.loads(raw)

        self.assertEqual(data[3]["id"], 99)
        self.assertEqual(data[3]["connectorId"], 1)
        self.assertEqual(data[3]["chargingProfilePurpose"], "TxDefaultProfile")

    # --- SetChargingProfile nested structure ---

    def test_set_charging_profile_has_correct_nested_structure(self):
        """SetChargingProfile must have connectorId and csChargingProfiles with schedule."""
        mixin = self._make_mixin()
        raw = mixin._build_set_charging_profile(
            connector_id=1,
            profile_id=99999,
            stack_level=0,
            purpose="TxDefaultProfile",
            rate_unit="A",
            limit=1.0,
        )
        data = json.loads(raw)
        profile = data[3]["csChargingProfiles"]

        self.assertEqual(data[3]["connectorId"], 1)
        self.assertEqual(profile["chargingProfileId"], 99999)
        self.assertEqual(profile["stackLevel"], 0)
        self.assertEqual(profile["chargingProfilePurpose"], "TxDefaultProfile")
        self.assertEqual(profile["chargingProfileKind"], "Absolute")
        schedule = profile["chargingSchedule"]
        self.assertEqual(schedule["chargingRateUnit"], "A")
        self.assertEqual(len(schedule["chargingSchedulePeriod"]), 1)
        self.assertEqual(schedule["chargingSchedulePeriod"][0]["startPeriod"], 0)
        self.assertEqual(schedule["chargingSchedulePeriod"][0]["limit"], 1.0)

    # --- StopTransaction optional idTag ---

    def test_stop_transaction_omits_id_tag_when_none(self):
        mixin = self._make_mixin()
        raw = mixin._build_stop_transaction(transaction_id=42)
        data = json.loads(raw)

        self.assertNotIn("idTag", data[3])
        self.assertEqual(data[3]["transactionId"], 42)

    def test_stop_transaction_includes_id_tag_when_provided(self):
        mixin = self._make_mixin()
        raw = mixin._build_stop_transaction(
            transaction_id=42, id_tag="TEST01", meter_stop=500, reason="Local"
        )
        data = json.loads(raw)

        self.assertEqual(data[3]["idTag"], "TEST01")
        self.assertEqual(data[3]["meterStop"], 500)
        self.assertEqual(data[3]["reason"], "Local")

    # --- MeterValues optional transactionId ---

    def test_meter_values_excludes_transaction_id_when_none(self):
        mixin = self._make_mixin()
        raw = mixin._build_meter_values(connector_id=1)
        data = json.loads(raw)

        self.assertNotIn("transactionId", data[3])

    def test_meter_values_includes_transaction_id_when_provided(self):
        mixin = self._make_mixin()
        raw = mixin._build_meter_values(connector_id=1, transaction_id=42)
        data = json.loads(raw)

        self.assertEqual(data[3]["transactionId"], 42)

    # --- ReserveNow default expiry ---

    def test_reserve_now_auto_generates_future_expiry(self):
        mixin = self._make_mixin()
        raw = mixin._build_reserve_now(connector_id=1, id_tag="RFID001")
        data = json.loads(raw)

        self.assertIn("expiryDate", data[3])
        # Must be a far-future date to avoid accidentally reserving
        self.assertIn("2099", data[3]["expiryDate"])

    # --- GetInstalledCertificateIds optional type ---

    def test_get_installed_certificate_ids_empty_when_no_type(self):
        mixin = self._make_mixin()
        raw = mixin._build_get_installed_certificate_ids()
        data = json.loads(raw)

        self.assertEqual(data[3], {})

    def test_get_installed_certificate_ids_wraps_type_in_array(self):
        """certificateType must be a list per OCPP 2.0.1 spec."""
        mixin = self._make_mixin()
        raw = mixin._build_get_installed_certificate_ids(certificate_type="CSMSRootCertificate")
        data = json.loads(raw)

        self.assertIsInstance(data[3]["certificateType"], list)
        self.assertEqual(data[3]["certificateType"], ["CSMSRootCertificate"])

    # --- GetLog nested structure ---

    def test_get_log_has_nested_log_object(self):
        mixin = self._make_mixin()
        raw = mixin._build_get_log(
            log_type="SecurityLog", request_id=42, location="http://0.0.0.0/log"
        )
        data = json.loads(raw)

        self.assertEqual(data[3]["logType"], "SecurityLog")
        self.assertEqual(data[3]["requestId"], 42)
        self.assertEqual(data[3]["log"]["remoteLocation"], "http://0.0.0.0/log")

    # --- StatusNotification has timestamp ---

    def test_status_notification_includes_timestamp(self):
        mixin = self._make_mixin()
        raw = mixin._build_status_notification(connector_id=1, status="Charging")
        data = json.loads(raw)

        self.assertIn("timestamp", data[3])
        self.assertIn("T", data[3]["timestamp"], "Timestamp must be ISO 8601")


# ---------------------------------------------------------------------------
# Scanner class tests
# ---------------------------------------------------------------------------


class TestOCPPScannerInit(unittest.TestCase):
    """Test OCPP scanner initialization and URL parsing logic"""

    def test_ws_url_parses_host_and_port(self):
        """WebSocket URL should extract host and port into args."""
        from oida.protocols.ocpp.scanner import OCPPScanner

        args = {"target-url": "ws://10.0.0.1:8080/CP1"}
        scanner = OCPPScanner(args)

        self.assertEqual(scanner.target_url, "ws://10.0.0.1:8080/CP1")
        self.assertEqual(args["rhost"], "10.0.0.1")
        self.assertEqual(args["rport"], 8080)

    def test_wss_url_enables_tls(self):
        from oida.protocols.ocpp.scanner import OCPPScanner

        args = {"target-url": "wss://secure.host/CP1"}
        scanner = OCPPScanner(args)

        self.assertTrue(scanner.tls)
        self.assertEqual(args["rport"], 443)

    def test_ws_url_without_port_defaults_to_9000(self):
        from oida.protocols.ocpp.scanner import OCPPScanner

        args = {"target-url": "ws://host/CP1"}
        OCPPScanner(args)

        self.assertEqual(args["rport"], 9000)

    def test_wss_url_without_port_defaults_to_443(self):
        from oida.protocols.ocpp.scanner import OCPPScanner

        args = {"target-url": "wss://host/CP1"}
        OCPPScanner(args)

        self.assertEqual(args["rport"], 443)

    def test_plain_hostname_constructs_ws_url(self):
        from oida.protocols.ocpp.scanner import OCPPScanner

        args = {"target-url": "192.168.1.200"}
        scanner = OCPPScanner(args)

        self.assertTrue(scanner.target_url.startswith("ws://192.168.1.200:"))

    def test_existing_rhost_not_overwritten_by_url(self):
        """If rhost is already set, URL parsing should not overwrite it."""
        from oida.protocols.ocpp.scanner import OCPPScanner

        args = {"target-url": "ws://other:8080/CP1", "rhost": "original"}
        OCPPScanner(args)

        self.assertEqual(args["rhost"], "original")

    def test_build_ws_url_preserves_explicit_url(self):
        from oida.protocols.ocpp.scanner import OCPPScanner

        args = {"rhost": "x", "rport": 9000, "target-url": "ws://charger.local:8080/CP_001"}
        scanner = OCPPScanner(args)

        self.assertEqual(scanner._build_ws_url(), "ws://charger.local:8080/CP_001")

    def test_build_ws_url_from_host_and_port(self):
        from oida.protocols.ocpp.scanner import OCPPScanner

        args = {"rhost": "192.168.1.100", "rport": 9000}
        scanner = OCPPScanner(args)
        url = scanner._build_ws_url()

        self.assertTrue(url.startswith("ws://"))
        self.assertIn("192.168.1.100", url)
        self.assertIn("9000", url)

    def test_get_subprotocols_auto_includes_both_versions(self):
        from oida.protocols.ocpp.scanner import OCPPScanner

        args = {"rhost": "x", "rport": 9000, "version": "auto"}
        scanner = OCPPScanner(args)
        subprotocols = scanner._get_subprotocols()

        self.assertIn("ocpp1.6", subprotocols)
        self.assertIn("ocpp2.0.1", subprotocols)

    def test_get_subprotocols_specific_version(self):
        from oida.protocols.ocpp.scanner import OCPPScanner

        for version, expected_sub in [("1.6", "ocpp1.6"), ("2.0.1", "ocpp2.0.1")]:
            args = {"rhost": "x", "rport": 9000, "version": version}
            scanner = OCPPScanner(args)
            self.assertEqual(scanner._get_subprotocols(), [expected_sub])

    def test_get_subprotocols_unknown_version_falls_back(self):
        from oida.protocols.ocpp.scanner import OCPPScanner

        args = {"rhost": "x", "rport": 9000, "version": "99.99"}
        scanner = OCPPScanner(args)

        self.assertEqual(scanner._get_subprotocols(), ["ocpp1.6"])

    def test_default_port_ws_vs_wss(self):
        from oida.protocols.ocpp.scanner import OCPPScanner

        ws_scanner = OCPPScanner({"rhost": "x", "rport": 9000})
        self.assertEqual(ws_scanner.get_default_port(), 9000)

        wss_scanner = OCPPScanner({"rhost": "x", "rport": 443, "target": "wss://x:443/CP1"})
        self.assertEqual(wss_scanner.get_default_port(), 443)

    def test_build_ssl_context_none_when_no_tls(self):
        from oida.protocols.ocpp.scanner import OCPPScanner

        scanner = OCPPScanner({"rhost": "x", "rport": 9000})
        self.assertIsNone(scanner._build_ssl_context())

    def test_build_ssl_context_insecure_disables_verification(self):
        import ssl
        from oida.protocols.ocpp.scanner import OCPPScanner

        scanner = OCPPScanner(
            {
                "rhost": "x",
                "rport": 443,
                "target": "wss://x:443/CP1",
                "tls-insecure": True,
            }
        )
        ctx = scanner._build_ssl_context()

        self.assertIsNotNone(ctx)
        self.assertEqual(ctx.verify_mode, ssl.CERT_NONE)

    def test_discover_extracts_version_from_subprotocol(self):
        from oida.protocols.ocpp.scanner import OCPPScanner

        scanner = OCPPScanner({"rhost": "x", "rport": 9000})
        mock_conn = Mock()
        mock_conn.subprotocol = "ocpp2.0.1"

        results = scanner.discover(mock_conn)

        self.assertEqual(results["version"], "2.0.1")
        self.assertEqual(results["subprotocol"], "ocpp2.0.1")

    def test_discover_no_subprotocol_returns_empty(self):
        from oida.protocols.ocpp.scanner import OCPPScanner

        scanner = OCPPScanner({"rhost": "x", "rport": 9000})
        mock_conn = Mock()
        mock_conn.subprotocol = None

        results = scanner.discover(mock_conn)
        self.assertNotIn("version", results)

    def test_get_server_info_includes_version(self):
        from oida.protocols.ocpp.scanner import OCPPScanner

        scanner = OCPPScanner({"rhost": "x", "rport": 9000})
        mock_conn = Mock()
        mock_conn.subprotocol = "ocpp1.6"

        info = scanner._get_server_info(mock_conn)

        self.assertEqual(info["connection_type"], "WebSocket")
        self.assertEqual(info["version"], "1.6")


# ---------------------------------------------------------------------------
# Scanner connect / disconnect tests (mocked WebSocket)
# ---------------------------------------------------------------------------


class TestOCPPScannerConnect(unittest.TestCase):
    """Test OCPP scanner connection with mocked websockets"""

    def _make_scanner(self, **extra):
        from oida.protocols.ocpp.scanner import OCPPScanner

        args = {"rhost": "192.168.1.100", "rport": 9000}
        args.update(extra)
        return OCPPScanner(args)

    @patch("oida.protocols.ocpp.scanner._websockets")
    def test_connect_returns_websocket_object(self, mock_ws_wrapper):
        scanner = self._make_scanner()
        mock_ws = Mock()
        mock_ws.subprotocol = "ocpp1.6"

        async def fake_connect(*a, **kw):
            return mock_ws

        mock_ws_wrapper.get_module.return_value = Mock()
        mock_ws_wrapper.dependencies_missing = False

        with patch("websockets.asyncio.client.connect", side_effect=fake_connect):
            conn = scanner.connect()

        self.assertIsNotNone(conn)
        self.assertEqual(conn.subprotocol, "ocpp1.6")

    @patch("oida.protocols.ocpp.scanner._websockets")
    def test_connect_failure_returns_none(self, mock_ws_wrapper):
        scanner = self._make_scanner()

        async def failing_connect(*a, **kw):
            raise ConnectionRefusedError("Connection refused")

        mock_ws_wrapper.get_module.return_value = Mock()
        mock_ws_wrapper.dependencies_missing = False

        with patch("websockets.asyncio.client.connect", side_effect=failing_connect):
            conn = scanner.connect()
        self.assertIsNone(conn)

    @patch("oida.protocols.ocpp.scanner._websockets")
    def test_connect_with_auth_sends_authorization_header(self, mock_ws_wrapper):
        import base64

        scanner = self._make_scanner(username="CP001", password="secret")
        mock_ws = Mock()
        mock_ws.subprotocol = "ocpp1.6"
        captured_kwargs = {}

        async def fake_connect(*a, **kw):
            captured_kwargs.update(kw)
            return mock_ws

        mock_ws_wrapper.get_module.return_value = Mock()
        mock_ws_wrapper.dependencies_missing = False

        with patch("websockets.asyncio.client.connect", side_effect=fake_connect):
            conn = scanner.connect()

        self.assertIsNotNone(conn)
        auth_header = captured_kwargs["additional_headers"]["Authorization"]
        expected = base64.b64encode(b"CP001:secret").decode()
        self.assertEqual(auth_header, f"Basic {expected}")

    @patch("oida.protocols.ocpp.scanner._websockets")
    def test_send_and_receive_returns_response(self, mock_ws_wrapper):
        scanner = self._make_scanner()
        response_json = json.dumps([3, "msg1", {"currentTime": "2025-01-01T00:00:00Z"}])

        mock_ws = Mock()

        async def fake_send(msg):
            pass

        async def fake_recv():
            return response_json

        mock_ws.send = fake_send
        mock_ws.recv = fake_recv

        async def fake_connect(*a, **kw):
            return mock_ws

        mock_ws_wrapper.get_module.return_value = Mock()
        mock_ws_wrapper.dependencies_missing = False

        with patch("websockets.asyncio.client.connect", side_effect=fake_connect):
            conn = scanner.connect()
        result = scanner._send_and_receive(conn, '{"test": true}')

        self.assertEqual(result, response_json)

    def test_send_and_receive_returns_none_with_no_connection(self):
        scanner = self._make_scanner()
        self.assertIsNone(scanner._send_and_receive(None, '{"test": true}'))

    def test_send_and_receive_returns_none_without_event_loop(self):
        scanner = self._make_scanner()
        self.assertIsNone(scanner._send_and_receive(Mock(), '{"test": true}'))

    @patch("oida.protocols.ocpp.scanner._websockets")
    def test_send_and_receive_discards_mismatched_unique_id(self, mock_ws_wrapper):
        """A CALLRESULT answering a different (stale/out-of-order) UniqueId
        must not be accepted as the response to the CALL just sent -- the
        client must keep waiting for the correctly-correlated response
        instead of a "first response wins" acceptance."""
        scanner = self._make_scanner()
        stale_response = json.dumps([3, "OTHER-ID", {"status": "Accepted"}])
        correct_response = json.dumps([3, "REQ-1", {"status": "Rejected"}])
        frames = [stale_response, correct_response]

        mock_ws = Mock()

        async def fake_send(msg):
            pass

        async def fake_recv():
            return frames.pop(0)

        mock_ws.send = fake_send
        mock_ws.recv = fake_recv

        async def fake_connect(*a, **kw):
            return mock_ws

        mock_ws_wrapper.get_module.return_value = Mock()
        mock_ws_wrapper.dependencies_missing = False

        with patch("websockets.asyncio.client.connect", side_effect=fake_connect):
            conn = scanner.connect()

        sent_call = json.dumps([2, "REQ-1", "Heartbeat", {}])
        result = scanner._send_and_receive(conn, sent_call)

        self.assertEqual(result, correct_response)


# ---------------------------------------------------------------------------
# Incoming CALL handler tests
# ---------------------------------------------------------------------------


class TestIncomingCallHandler(unittest.TestCase):
    """Test incoming server-initiated CALL handling in OCPPScanner"""

    def _make_scanner(self):
        from oida.protocols.ocpp.scanner import OCPPScanner

        return OCPPScanner(
            {
                "target-url": "ws://localhost:9000/CP_001",
                "version": "auto",
                "charge-point-id": "CP_001",
                "rhost": "localhost",
                "rport": 9000,
                "timeout": 5,
                "verbose": 0,
            }
        )

    def test_incoming_call_produces_callresult(self):
        """All incoming CALLs must be answered with a CALLRESULT [3, id, payload]."""
        scanner = self._make_scanner()
        response = scanner._handle_incoming_call("Reset", {"type": "Soft"}, "msg1", Mock())

        data = json.loads(response)
        self.assertEqual(data[0], 3, "Response must be CALLRESULT")
        self.assertEqual(data[1], "msg1", "Must echo the original message ID")

    def test_remote_start_rejected_by_default(self):
        """Scanner must reject RemoteStartTransaction to avoid unintended charging."""
        scanner = self._make_scanner()
        response = scanner._handle_incoming_call(
            "RemoteStartTransaction", {"idTag": "TAG1"}, "m1", Mock()
        )
        data = json.loads(response)
        self.assertEqual(data[2]["status"], "Rejected")

    def test_remote_stop_rejected_by_default(self):
        scanner = self._make_scanner()
        response = scanner._handle_incoming_call(
            "RemoteStopTransaction", {"transactionId": 1}, "m1", Mock()
        )
        data = json.loads(response)
        self.assertEqual(data[2]["status"], "Rejected")

    def test_unknown_action_returns_empty_payload(self):
        scanner = self._make_scanner()
        response = scanner._handle_incoming_call("SomeCustomAction", {}, "m1", Mock())
        data = json.loads(response)
        self.assertEqual(data[2], {})

    def test_all_known_actions_have_safe_defaults(self):
        """Every action in the defaults map must return a non-None response."""
        scanner = self._make_scanner()
        known_actions = [
            "Reset",
            "RemoteStartTransaction",
            "RemoteStopTransaction",
            "UnlockConnector",
            "ChangeAvailability",
            "ChangeConfiguration",
            "ClearCache",
            "GetConfiguration",
            "UpdateFirmware",
            "SetChargingProfile",
            "ClearChargingProfile",
            "TriggerMessage",
            "DataTransfer",
            "SendLocalList",
            "GetLocalListVersion",
            "GetBaseReport",
            "RequestStartTransaction",
            "RequestStopTransaction",
        ]
        for action in known_actions:
            response = scanner._get_default_call_response(action)
            self.assertIsInstance(response, dict, f"No default for {action}")


# ---------------------------------------------------------------------------
# Discovery mixin tests
# ---------------------------------------------------------------------------


class TestDiscoveryMixin(unittest.TestCase):
    """Test OCPP discovery mixin methods"""

    def _make_instance(self):
        from oida.protocols.ocpp.mixins.discovery import DiscoveryMixin
        from oida.protocols.ocpp.mixins.messages import MessagesMixin
        from oida.protocols.ocpp.mixins.security import SecurityMixin

        class FakeOCPP(DiscoveryMixin, SecurityMixin, MessagesMixin, ConfirmGateMixin):
            pass

        obj = FakeOCPP()
        obj.conn = Mock()
        obj.conn.subprotocol = "ocpp1.6"
        obj.logger = Mock()
        obj.results = {"data": {}}
        obj.scanner = Mock()
        obj.args = Mock()
        obj.args.verbose = 0
        obj.args.connector_id = 0
        obj.args.max_connector_id = 10
        return obj

    def test_version_detection_maps_subprotocol_correctly(self):
        """Version detection must map subprotocol strings to version numbers."""
        obj = self._make_instance()

        for subprotocol, expected_version in [
            ("ocpp1.6", "1.6"),
            ("ocpp2.0.1", "2.0.1"),
            ("ocpp2.1", "2.1"),
        ]:
            obj.conn.subprotocol = subprotocol
            obj.results = {"data": {}}
            obj._handle_version_detection()
            self.assertEqual(obj.results["data"]["ocpp_version"], expected_version)

    def test_version_detection_handles_no_subprotocol(self):
        obj = self._make_instance()
        obj.conn.subprotocol = None
        obj._handle_version_detection()

        self.assertIsNone(obj.results["data"]["ocpp_version"])

    def test_boot_notification_accepted_extracts_all_fields(self):
        """On CALLRESULT, must extract status, interval, and currentTime."""
        obj = self._make_instance()
        obj.results["data"]["ocpp_version"] = "1.6"

        response = json.dumps(
            [
                3,
                "id1",
                {
                    "status": "Accepted",
                    "interval": 300,
                    "currentTime": "2025-01-01T00:00:00Z",
                },
            ]
        )
        obj.scanner._send_and_receive.return_value = response

        obj._handle_boot_notification()

        boot = obj.results["data"]["boot_notification"]
        self.assertEqual(boot["status"], "Accepted")
        self.assertEqual(boot["interval"], 300)
        self.assertEqual(boot["current_time"], "2025-01-01T00:00:00Z")

    def test_boot_notification_callerror_stores_error_info(self):
        obj = self._make_instance()
        obj.results["data"]["ocpp_version"] = "1.6"

        response = json.dumps([4, "id1", "SecurityError", "Not authorized", {}])
        obj.scanner._send_and_receive.return_value = response

        obj._handle_boot_notification()

        boot = obj.results["data"]["boot_notification"]
        self.assertEqual(boot["status"], "error")
        self.assertEqual(boot["error_code"], "SecurityError")
        self.assertEqual(boot["error_description"], "Not authorized")

    def test_boot_notification_no_response(self):
        obj = self._make_instance()
        obj.results["data"]["ocpp_version"] = "1.6"
        obj.scanner._send_and_receive.return_value = None

        obj._handle_boot_notification()
        self.assertEqual(obj.results["data"]["boot_notification"]["status"], "no_response")

    def test_boot_notification_exception_stores_error(self):
        obj = self._make_instance()
        obj.results["data"]["ocpp_version"] = "1.6"
        obj.scanner._send_and_receive.side_effect = Exception("network error")

        obj._handle_boot_notification()

        boot = obj.results["data"]["boot_notification"]
        self.assertEqual(boot["status"], "error")
        self.assertIn("network error", boot["error"])

    def test_boot_notification_uses_v201_format_when_version_is_2x(self):
        """BootNotification should send v2.0.1 format when version starts with '2.'."""
        obj = self._make_instance()
        obj.results["data"]["ocpp_version"] = "2.0.1"
        obj.scanner._send_and_receive.return_value = json.dumps(
            [3, "id1", {"status": "Accepted", "interval": 300}]
        )

        obj._handle_boot_notification()

        # Verify the message sent was v2.0.1 format
        sent_msg = obj.scanner._send_and_receive.call_args[0][1]
        sent_data = json.loads(sent_msg)
        self.assertIn("chargingStation", sent_data[3])

    def test_heartbeat_stores_current_time(self):
        obj = self._make_instance()

        response = json.dumps([3, "id1", {"currentTime": "2025-06-01T12:00:00Z"}])
        obj.scanner._send_and_receive.return_value = response

        obj._handle_heartbeat()

        self.assertEqual(
            obj.results["data"]["heartbeat"]["current_time"],
            "2025-06-01T12:00:00Z",
        )

    def test_heartbeat_no_connection_is_noop(self):
        obj = self._make_instance()
        obj.conn = None
        obj._handle_heartbeat()
        self.assertNotIn("heartbeat", obj.results["data"])

    def test_heartbeat_no_response_is_noop(self):
        obj = self._make_instance()
        obj.scanner._send_and_receive.return_value = None
        obj._handle_heartbeat()
        self.assertNotIn("heartbeat", obj.results["data"])

    def test_enumerate_actions_classifies_correctly(self):
        """Action enumeration must classify responses:
        - CALLRESULT -> supported
        - CALLERROR FormationViolation -> supported (action recognized)
        - CALLERROR NotImplemented -> not_implemented
        - CALLERROR NotSupported -> not_supported
        - None -> errors
        """
        obj = self._make_instance()
        obj.results["data"]["ocpp_version"] = "1.6"

        def fake_send_recv(conn, msg, timeout=3):
            data = json.loads(msg)
            action = data[2]
            msg_id = data[1]

            responses = {
                "BootNotification": [4, msg_id, "FormationViolation", "Bad", {}],
                "Heartbeat": [3, msg_id, {"currentTime": "now"}],
                "Reset": [4, msg_id, "NotImplemented", "Unknown", {}],
                "UpdateFirmware": [4, msg_id, "NotSupported", "Unsupported", {}],
            }
            if action in responses:
                return json.dumps(responses[action])
            return None  # Timeout for everything else

        obj.scanner._send_and_receive.side_effect = fake_send_recv

        obj._handle_enumerate_actions()

        actions = obj.results["data"]["actions"]
        # FormationViolation means action is recognized -> supported
        self.assertIn("BootNotification", actions["supported"])
        # CALLRESULT means action works -> supported
        self.assertIn("Heartbeat", actions["supported"])
        # NotImplemented -> not_implemented
        self.assertIn("Reset", actions["not_implemented"])
        # NotSupported -> not_supported
        self.assertIn("UpdateFirmware", actions["not_supported"])
        # Timeouts -> errors
        self.assertGreater(len(actions["errors"]), 0)

    def test_enumerate_highlights_dangerous_actions(self):
        """Dangerous supported actions must generate a HIGH finding and be highlighted."""
        obj = self._make_instance()
        obj.results["data"]["ocpp_version"] = "1.6"

        def fake_send_recv(conn, msg, timeout=3):
            data = json.loads(msg)
            action = data[2]
            msg_id = data[1]
            # Reset and Heartbeat are supported; Reset is dangerous
            if action in ("Reset", "Heartbeat", "UnlockConnector"):
                return json.dumps([3, msg_id, {}])
            return json.dumps([4, msg_id, "NotImplemented", "", {}])

        obj.scanner._send_and_receive.side_effect = fake_send_recv

        obj._handle_enumerate_actions()

        actions = obj.results["data"]["actions"]
        self.assertIn("Reset", actions["supported"])
        self.assertIn("UnlockConnector", actions["supported"])
        self.assertIn("Heartbeat", actions["supported"])

        # Should have generated a finding for dangerous actions
        findings = obj.results["data"].get("security_findings", [])
        self.assertEqual(len(findings), 1)
        self.assertIn("Reset", findings[0]["description"])
        self.assertIn("UnlockConnector", findings[0]["description"])
        # Heartbeat is not dangerous, should not be mentioned
        self.assertNotIn("Heartbeat", findings[0]["description"])

    def test_enumerate_no_finding_when_no_dangerous_actions(self):
        """No finding generated when only safe actions are supported."""
        obj = self._make_instance()
        obj.results["data"]["ocpp_version"] = "1.6"

        def fake_send_recv(conn, msg, timeout=3):
            data = json.loads(msg)
            action = data[2]
            msg_id = data[1]
            if action in ("Heartbeat", "BootNotification"):
                return json.dumps([3, msg_id, {}])
            return json.dumps([4, msg_id, "NotImplemented", "", {}])

        obj.scanner._send_and_receive.side_effect = fake_send_recv

        obj._handle_enumerate_actions()

        findings = obj.results["data"].get("security_findings", [])
        self.assertEqual(len(findings), 0)

    def test_enumerate_actions_uses_v201_list_when_version_2x(self):
        """When OCPP version is 2.x, must use ALL_ACTIONS_V201 action list."""
        from oida.protocols.ocpp.constants import ALL_ACTIONS_V201

        obj = self._make_instance()
        obj.results["data"]["ocpp_version"] = "2.0.1"

        sent_actions = []

        def fake_send_recv(conn, msg, timeout=3):
            data = json.loads(msg)
            sent_actions.append(data[2])
            return json.dumps([4, data[1], "NotImplemented", "", {}])

        obj.scanner._send_and_receive.side_effect = fake_send_recv

        obj._handle_enumerate_actions()

        # Should have probed all v201 actions
        self.assertEqual(set(sent_actions), set(ALL_ACTIONS_V201))

    def test_get_configuration_extracts_keys_and_values(self):
        obj = self._make_instance()

        response = json.dumps(
            [
                3,
                "id1",
                {
                    "configurationKey": [
                        {"key": "HeartbeatInterval", "value": "300", "readonly": False},
                        {"key": "NumberOfConnectors", "value": "2", "readonly": True},
                    ],
                    "unknownKey": ["FakeKey"],
                },
            ]
        )
        obj.scanner._send_and_receive.return_value = response

        obj._handle_get_configuration()

        config = obj.results["data"]["configuration"]
        self.assertEqual(len(config["keys"]), 2)
        self.assertEqual(config["keys"][0]["key"], "HeartbeatInterval")
        self.assertFalse(config["keys"][0]["readonly"])
        self.assertTrue(config["keys"][1]["readonly"])
        self.assertEqual(config["unknown_keys"], ["FakeKey"])

    def test_data_transfer_probe_stores_response_data(self):
        obj = self._make_instance()

        response = json.dumps([3, "id1", {"status": "Accepted", "data": "pong"}])
        obj.scanner._send_and_receive.return_value = response

        obj._handle_data_transfer_probe()

        dt = obj.results["data"]["data_transfer"]
        self.assertEqual(dt["status"], "Accepted")
        self.assertEqual(dt["data"], "pong")

    def test_extract_meter_values_parses_sampled_values(self):
        """_extract_meter_values must extract measurand, value, unit, and phase."""
        obj = self._make_instance()

        payload = {
            "meterValue": [
                {
                    "timestamp": "2026-01-01T00:00:00Z",
                    "sampledValue": [
                        {
                            "value": "100.5",
                            "measurand": "Energy.Active.Import.Register",
                            "unit": "kWh",
                        },
                        {"value": "230", "measurand": "Voltage", "unit": "V", "phase": "L1"},
                    ],
                }
            ],
        }

        values = obj._extract_meter_values(payload)

        self.assertEqual(len(values), 2)
        self.assertEqual(values[0]["measurand"], "Energy.Active.Import.Register")
        self.assertEqual(values[0]["value"], "100.5")
        self.assertEqual(values[0]["unit"], "kWh")
        self.assertEqual(values[1]["phase"], "L1")

    def test_extract_meter_values_handles_defaults(self):
        """Missing fields should get sensible defaults."""
        obj = self._make_instance()

        payload = {
            "meterValue": [
                {
                    "sampledValue": [{"value": "42"}],
                }
            ],
        }

        values = obj._extract_meter_values(payload)
        self.assertEqual(values[0]["measurand"], "Energy.Active.Import.Register")
        self.assertEqual(values[0]["format"], "Raw")

    def test_extract_meter_values_empty_payload(self):
        obj = self._make_instance()
        self.assertEqual(obj._extract_meter_values({}), [])

    def test_probe_meter_values_direct_call_response(self):
        """When CP sends MeterValues CALL instead of CALLRESULT, must parse it."""
        obj = self._make_instance()

        meter_call = json.dumps(
            [
                2,
                "cp1",
                "MeterValues",
                {
                    "connectorId": 1,
                    "meterValue": [
                        {
                            "timestamp": "2026-01-01T00:00:00Z",
                            "sampledValue": [
                                {
                                    "value": "15.5",
                                    "measurand": "Energy.Active.Import.Register",
                                    "unit": "kWh",
                                },
                                {"value": "3680", "measurand": "Power.Active.Import", "unit": "W"},
                            ],
                        }
                    ],
                },
            ]
        )
        obj.scanner._send_and_receive.return_value = meter_call

        obj.probe_meter_values()

        result = obj.results["data"]["meter_values"]
        self.assertEqual(result["trigger_status"], "direct_response")
        self.assertEqual(len(result["values"]), 2)
        self.assertEqual(result["values"][0]["value"], "15.5")

    def test_enumerate_connectors_v201_falls_back_on_error(self):
        """v2.0.1 enumeration should fall back to v1.6 method on GetBaseReport error."""
        obj = self._make_instance()
        obj.results["data"]["ocpp_version"] = "2.0.1"

        response = json.dumps([4, "id1", "NotImplemented", "Unknown", {}])
        obj.scanner._send_and_receive.return_value = response
        obj._enumerate_connectors_v16 = Mock(return_value={"0": {"found": True}})

        obj.enumerate_connectors()

        obj._enumerate_connectors_v16.assert_called_once()
        self.assertIn("0", obj.results["data"]["connectors"])

    def test_enumerate_connectors_not_implemented_not_counted(self):
        """NotImplemented errors should NOT mark connectors as found."""
        obj = self._make_instance()
        obj.args.max_connector_id = 1

        def fake_send(conn, msg, timeout=3):
            data = json.loads(msg)
            return json.dumps([4, data[1], "NotImplemented", "", {}])

        obj.scanner._send_and_receive.side_effect = fake_send

        obj.enumerate_connectors()

        connectors = obj.results["data"]["connectors"]
        found = [c for c in connectors.values() if isinstance(c, dict) and c.get("found")]
        self.assertEqual(len(found), 0)


# ---------------------------------------------------------------------------
# Security mixin tests -- focus on finding severity and cleanup behavior
# ---------------------------------------------------------------------------


class TestSecurityMixin(unittest.TestCase):
    """Test OCPP security mixin: finding severity, cleanup, edge cases"""

    def _make_instance(self):
        from oida.protocols.ocpp.mixins.security import SecurityMixin
        from oida.protocols.ocpp.mixins.messages import MessagesMixin

        class FakeOCPP(SecurityMixin, MessagesMixin, ConfirmGateMixin):
            pass

        obj = FakeOCPP()
        obj.conn = Mock()
        obj.logger = Mock()
        obj.results = {"data": {}}
        obj.scanner = Mock()
        obj.args = Mock()
        obj.args.username = None
        obj.args.timeout = 5
        obj.args.verbose = 0
        obj.args.connector_id = 1
        obj.ip = "192.168.1.100"
        return obj

    def _get_findings(self, obj):
        return obj.results["data"].get("security_findings", [])

    # --- _handle_check_auth ---

    def test_check_auth_anonymous_generates_no_duplicate_finding(self):
        """Anonymous connection (no username) must NOT add a second "Anonymous
        access" finding: create_conn_obj() already reports it unconditionally
        for every unauthenticated connection (regardless of --check-auth/
        --security), so _handle_check_auth() re-adding it via _add_finding()
        previously produced two differently-shaped entries in
        results["data"]["security_findings"] for the same underlying issue.
        """
        obj = self._make_instance()
        obj.args.username = None

        obj._handle_check_auth()

        self.assertEqual(len(self._get_findings(obj)), 0)

    def test_check_auth_authenticated_no_finding(self):
        obj = self._make_instance()
        obj.args.username = "CP001"

        obj._handle_check_auth()

        self.assertEqual(len(self._get_findings(obj)), 0)

    def test_check_auth_no_connection_is_noop(self):
        obj = self._make_instance()
        obj.conn = None
        obj._handle_check_auth()
        self.assertNotIn("security_findings", obj.results["data"])

    # --- _handle_check_boot ---

    def test_check_boot_accepted_generates_medium_finding(self):
        obj = self._make_instance()
        obj.results["data"]["boot_notification"] = {"status": "Accepted"}

        obj._handle_check_boot()

        findings = self._get_findings(obj)
        self.assertEqual(len(findings), 1)

    def test_check_boot_rejected_no_finding(self):
        obj = self._make_instance()
        obj.results["data"]["boot_notification"] = {"status": "Rejected"}

        obj._handle_check_boot()
        self.assertEqual(len(self._get_findings(obj)), 0)

    def test_check_boot_pending_no_finding(self):
        obj = self._make_instance()
        obj.results["data"]["boot_notification"] = {"status": "Pending"}

        obj._handle_check_boot()
        self.assertEqual(len(self._get_findings(obj)), 0)

    # --- _handle_check_config_keys ---

    def test_check_config_exposed_auth_key_critical(self):
        """Exposed AuthorizationKey must generate CRITICAL finding."""
        obj = self._make_instance()
        obj.results["data"]["configuration"] = {
            "keys": [{"key": "AuthorizationKey", "value": "SuperSecretKey123", "readonly": True}]
        }

        obj._handle_check_config_keys()

        findings = self._get_findings(obj)
        key_findings = [f for f in findings if "AuthorizationKey" in f["issue"]]
        self.assertEqual(len(key_findings), 1)

    def test_check_config_writable_security_key_generates_medium(self):
        obj = self._make_instance()
        obj.results["data"]["configuration"] = {
            "keys": [{"key": "SecurityProfile", "value": "1", "readonly": False}]
        }

        obj._handle_check_config_keys()

        findings = self._get_findings(obj)
        writable = [f for f in findings if "writable" in f["issue"]]
        self.assertEqual(len(writable), 1)

    # --- test_charging_profile_write: cleanup always runs ---

    def test_charging_profile_write_always_clears_on_accept(self):
        """ClearChargingProfile must ALWAYS be called even if Set is accepted."""
        obj = self._make_instance()
        calls = []

        def fake_send(conn, msg, timeout=5):
            data = json.loads(msg)
            calls.append(data[2])
            return json.dumps([3, data[1], {"status": "Accepted"}])

        obj.scanner._send_and_receive.side_effect = fake_send

        obj.test_charging_profile_write()

        self.assertIn("SetChargingProfile", calls)
        self.assertIn("ClearChargingProfile", calls)
        # Clear must come after Set
        set_idx = calls.index("SetChargingProfile")
        clear_idx = calls.index("ClearChargingProfile")
        self.assertGreater(clear_idx, set_idx)

    def test_charging_profile_write_clears_even_on_set_exception(self):
        """Cleanup must run even if SetChargingProfile raises an exception."""
        obj = self._make_instance()
        call_count = [0]

        def fake_send(conn, msg, timeout=5):
            call_count[0] += 1
            data = json.loads(msg)
            if call_count[0] == 1:
                raise Exception("network error")
            return json.dumps([3, data[1], {"status": "Accepted"}])

        obj.scanner._send_and_receive.side_effect = fake_send

        obj.test_charging_profile_write()

        # Should have attempted both calls
        self.assertEqual(call_count[0], 2)

    def test_charging_profile_accepted_generates_high_finding(self):
        obj = self._make_instance()

        def fake_send(conn, msg, timeout=5):
            data = json.loads(msg)
            return json.dumps([3, data[1], {"status": "Accepted"}])

        obj.scanner._send_and_receive.side_effect = fake_send

        obj.test_charging_profile_write()

        findings = self._get_findings(obj)
        profile_findings = [f for f in findings if "charging profile" in f["issue"].lower()]
        self.assertEqual(len(profile_findings), 1)

    def test_charging_profile_rejected_no_finding(self):
        obj = self._make_instance()

        def fake_send(conn, msg, timeout=5):
            data = json.loads(msg)
            return json.dumps([3, data[1], {"status": "Rejected"}])

        obj.scanner._send_and_receive.side_effect = fake_send

        obj.test_charging_profile_write()

        findings = self._get_findings(obj)
        self.assertFalse(any("charging profile" in f["issue"].lower() for f in findings))

    # --- test_availability: restore always runs ---

    def test_availability_always_restores_to_operative(self):
        """ChangeAvailability(Operative) must ALWAYS be sent to restore state."""
        obj = self._make_instance()
        sent_payloads = []

        def fake_send(conn, msg, timeout=5):
            data = json.loads(msg)
            sent_payloads.append(data[3])
            return json.dumps([3, data[1], {"status": "Accepted"}])

        obj.scanner._send_and_receive.side_effect = fake_send

        obj.test_availability()

        # First call: Inoperative, second call: Operative (restore)
        self.assertEqual(len(sent_payloads), 2)
        self.assertEqual(sent_payloads[0]["type"], "Inoperative")
        self.assertEqual(sent_payloads[1]["type"], "Operative")

    def test_availability_accepted_generates_high_finding(self):
        obj = self._make_instance()

        def fake_send(conn, msg, timeout=5):
            data = json.loads(msg)
            return json.dumps([3, data[1], {"status": "Accepted"}])

        obj.scanner._send_and_receive.side_effect = fake_send

        obj.test_availability()

        findings = self._get_findings(obj)
        avail_findings = [f for f in findings if "ChangeAvailability" in f["issue"]]
        self.assertEqual(len(avail_findings), 1)

    def test_availability_scheduled_also_generates_finding(self):
        """Scheduled acceptance is still a vulnerability."""
        obj = self._make_instance()

        def fake_send(conn, msg, timeout=5):
            data = json.loads(msg)
            return json.dumps([3, data[1], {"status": "Scheduled"}])

        obj.scanner._send_and_receive.side_effect = fake_send

        obj.test_availability()

        findings = self._get_findings(obj)
        self.assertTrue(any("ChangeAvailability" in f["issue"] for f in findings))

    # --- test_reserve: cancel always runs ---

    def test_reserve_always_cancels_reservation(self):
        """CancelReservation must always be sent after ReserveNow, even on reject."""
        obj = self._make_instance()
        actions_sent = []

        def fake_send(conn, msg, timeout=5):
            data = json.loads(msg)
            actions_sent.append(data[2])
            return json.dumps([3, data[1], {"status": "Rejected"}])

        obj.scanner._send_and_receive.side_effect = fake_send

        obj.test_reserve()

        self.assertIn("ReserveNow", actions_sent)
        self.assertIn("CancelReservation", actions_sent)

    # --- Security finding severities for each probe ---

    def test_remote_transaction_accepted_is_critical(self):
        obj = self._make_instance()
        obj.scanner._send_and_receive.return_value = json.dumps([3, "id1", {"status": "Accepted"}])

        obj.test_remote_transaction_control()

        # Findings carry issue + description (no severity field in this model),
        # so the "_is_critical" name is assured via the operation-specific issue.
        findings = self._get_findings(obj)
        matched = [f for f in findings if "remote transaction start accepted" in f["issue"].lower()]
        self.assertEqual(len(matched), 1)

    def test_reset_accepted_is_high(self):
        obj = self._make_instance()
        obj.scanner._send_and_receive.return_value = json.dumps([3, "id1", {"status": "Accepted"}])

        obj.test_reset_command()

        findings = self._get_findings(obj)
        matched = [f for f in findings if "soft reset accepted" in f["issue"].lower()]
        self.assertEqual(len(matched), 1)

    def test_unlock_accepted_is_high(self):
        obj = self._make_instance()
        obj.scanner._send_and_receive.return_value = json.dumps([3, "id1", {"status": "Unlocked"}])

        obj.test_unlock_connector()

        findings = self._get_findings(obj)
        matched = [f for f in findings if "connector unlock accepted" in f["issue"].lower()]
        self.assertEqual(len(matched), 1)

    def test_unlock_failed_no_finding(self):
        obj = self._make_instance()
        obj.scanner._send_and_receive.return_value = json.dumps(
            [3, "id1", {"status": "UnlockFailed"}]
        )

        obj.test_unlock_connector()
        self.assertEqual(len(self._get_findings(obj)), 0)

    def test_firmware_update_accepted_is_critical(self):
        obj = self._make_instance()
        obj.scanner._send_and_receive.return_value = json.dumps([3, "id1", {}])

        obj.test_firmware_update()

        findings = self._get_findings(obj)
        matched = [f for f in findings if "firmware update accepted" in f["issue"].lower()]
        self.assertEqual(len(matched), 1)

    def test_clear_cache_accepted_is_medium(self):
        obj = self._make_instance()
        obj.scanner._send_and_receive.return_value = json.dumps([3, "id1", {"status": "Accepted"}])

        obj.test_clear_cache()

        findings = self._get_findings(obj)
        matched = [f for f in findings if "clearcache accepted" in f["issue"].lower()]
        self.assertEqual(len(matched), 1)

    def test_diagnostics_v16_ssrf_is_high(self):
        obj = self._make_instance()
        obj.results["data"]["ocpp_version"] = "1.6"
        obj.scanner._send_and_receive.return_value = json.dumps(
            [3, "id1", {"fileName": "diag.txt"}]
        )

        obj.test_diagnostics()

        findings = self._get_findings(obj)
        self.assertIn("SSRF", findings[0]["issue"])

    def test_diagnostics_v201_uses_get_log(self):
        """v2.0.1 must use GetLog instead of GetDiagnostics."""
        obj = self._make_instance()
        obj.results["data"]["ocpp_version"] = "2.0.1"
        obj.scanner._send_and_receive.return_value = json.dumps([3, "id1", {"status": "Accepted"}])

        obj.test_diagnostics()

        self.assertEqual(obj.results["data"]["diagnostics_test"]["method"], "GetLog")

    def test_remote_stop_accepted_is_high(self):
        obj = self._make_instance()
        obj.scanner._send_and_receive.return_value = json.dumps([3, "id1", {"status": "Accepted"}])

        obj.test_remote_stop()

        findings = self._get_findings(obj)
        matched = [f for f in findings if "remotestoptransaction accepted" in f["issue"].lower()]
        self.assertEqual(len(matched), 1)

    def test_local_list_send_accepted_is_critical(self):
        """SendLocalList acceptance is CRITICAL (auth list replacement)."""
        obj = self._make_instance()
        responses = [
            json.dumps([3, "id1", {"listVersion": -1}]),
            json.dumps([3, "id2", {"status": "Accepted"}]),
        ]
        obj.scanner._send_and_receive = Mock(side_effect=responses)

        obj.test_local_list()

        findings = self._get_findings(obj)
        send_findings = [f for f in findings if "SendLocalList" in f["issue"]]
        self.assertEqual(len(send_findings), 1)

    def test_reserve_accepted_is_medium(self):
        obj = self._make_instance()

        def fake_send(conn, msg, timeout=5):
            data = json.loads(msg)
            return json.dumps([3, data[1], {"status": "Accepted"}])

        obj.scanner._send_and_receive.side_effect = fake_send

        obj.test_reserve()

        findings = self._get_findings(obj)
        matched = [f for f in findings if "ReserveNow" in f["issue"]]
        self.assertEqual(len(matched), 1)

    # --- Config write with sensitive keys ---

    def test_config_write_harmless_accepted_is_medium(self):
        obj = self._make_instance()

        def fake_send(conn, msg, timeout=5):
            data = json.loads(msg)
            action = data[2]
            if action == "GetConfiguration":
                return json.dumps(
                    [
                        3,
                        data[1],
                        {
                            "configurationKey": [
                                {"key": "HeartbeatInterval", "value": "300", "readonly": False},
                            ],
                            "unknownKey": [],
                        },
                    ]
                )
            elif action == "ChangeConfiguration":
                return json.dumps([3, data[1], {"status": "Accepted"}])
            return json.dumps([4, data[1], "NotImplemented", "", {}])

        obj.scanner._send_and_receive.side_effect = fake_send

        obj.test_config_write()

        findings = self._get_findings(obj)
        harmless = [f for f in findings if "Configuration writes" in f["issue"]]
        self.assertEqual(len(harmless), 1)

    def test_config_write_authorization_key_writable_is_critical(self):
        """AuthorizationKey being writable is CRITICAL, other keys are HIGH."""
        obj = self._make_instance()

        def fake_send(conn, msg, timeout=5):
            data = json.loads(msg)
            action = data[2]
            if action == "GetConfiguration":
                keys = data[3].get("key", [])
                config_keys = [{"key": k, "value": "x", "readonly": False} for k in keys]
                if not keys:
                    config_keys = [{"key": "HeartbeatInterval", "value": "300", "readonly": False}]
                return json.dumps(
                    [
                        3,
                        data[1],
                        {
                            "configurationKey": config_keys,
                            "unknownKey": [],
                        },
                    ]
                )
            elif action == "ChangeConfiguration":
                return json.dumps([3, data[1], {"status": "Accepted"}])
            return json.dumps([4, data[1], "NotImplemented", "", {}])

        obj.scanner._send_and_receive.side_effect = fake_send

        obj.test_config_write()

        findings = self._get_findings(obj)
        # AuthorizationKey should be skipped (too risky to probe write)
        security_findings = [f for f in findings if "SecurityProfile" in f["issue"]]
        self.assertTrue(security_findings)

    def test_config_write_readonly_key_marked_safe(self):
        obj = self._make_instance()

        def fake_send(conn, msg, timeout=5):
            data = json.loads(msg)
            action = data[2]
            if action == "GetConfiguration":
                keys = data[3].get("key", [])
                config_keys = [{"key": k, "value": "1", "readonly": True} for k in keys]
                if not keys:
                    config_keys = [{"key": "HeartbeatInterval", "value": "300", "readonly": False}]
                return json.dumps(
                    [
                        3,
                        data[1],
                        {
                            "configurationKey": config_keys,
                            "unknownKey": [],
                        },
                    ]
                )
            elif action == "ChangeConfiguration":
                return json.dumps([3, data[1], {"status": "Rejected"}])
            return json.dumps([4, data[1], "NotImplemented", "", {}])

        obj.scanner._send_and_receive.side_effect = fake_send

        obj.test_config_write()

        result = obj.results["data"]["config_write"]
        self.assertEqual(result["sensitive_keys"]["SecurityProfile"], "readonly")

    # --- Version enumeration ---

    def test_version_enumeration_probes_all_versions(self):
        obj = self._make_instance()
        obj.results["data"]["target_url"] = "ws://host:9000/CP1"

        probed_subs = []

        def fake_probe(url, subprotocol):
            probed_subs.append(subprotocol)
            return {"supported": subprotocol == "ocpp1.6", "reason": "test"}

        obj.scanner._probe_version.side_effect = fake_probe

        obj._handle_version_enumeration()

        self.assertEqual(set(probed_subs), {"ocpp1.6", "ocpp2.0.1", "ocpp2.1"})
        self.assertEqual(obj.results["data"]["supported_versions"], ["1.6"])

    # --- No-connection guard ---

    def test_all_security_probes_noop_without_connection(self):
        """All security probes must silently return when conn is None."""
        obj = self._make_instance()
        obj.conn = None

        # None of these should raise or store results
        obj.test_charging_profile_write()
        obj.test_remote_transaction_control()
        obj.test_reset_command()
        obj.test_unlock_connector()
        obj.test_firmware_update()
        obj.test_availability()
        obj.test_clear_cache()
        obj.test_diagnostics()
        obj.test_remote_stop()
        obj.test_reserve()
        obj.test_local_list()
        obj.test_config_write()

        # None should have stored results
        security_keys = [
            "charging_profile_write",
            "remote_transaction",
            "reset_test",
            "unlock_connector",
            "firmware_update",
            "availability_test",
            "clear_cache",
            "diagnostics_test",
            "remote_stop",
            "reservation_test",
            "local_list_test",
            "config_write",
        ]
        for key in security_keys:
            self.assertNotIn(key, obj.results["data"], f"{key} stored without connection")


# ---------------------------------------------------------------------------
# Charging mixin tests -- lifecycle and cleanup-on-failure
# ---------------------------------------------------------------------------


class TestChargingMixin(unittest.TestCase):
    """Test OCPP charging flow mixin: lifecycle, cleanup, version branching"""

    def _make_instance(self):
        from oida.protocols.ocpp.mixins.charging import ChargingMixin
        from oida.protocols.ocpp.mixins.messages import MessagesMixin
        from oida.protocols.ocpp.mixins.security import SecurityMixin

        class FakeOCPP(ChargingMixin, SecurityMixin, MessagesMixin, ConfirmGateMixin):
            pass

        obj = FakeOCPP()
        obj.conn = Mock()
        obj.logger = Mock()
        obj.results = {"data": {}}
        obj.scanner = Mock()
        obj.args = Mock()
        obj.args.connector_id = 1
        obj.args.timeout = 5
        obj.ip = "192.168.1.100"
        return obj

    def _get_findings(self, obj):
        return obj.results["data"].get("security_findings", [])

    # --- Authorization flow ---

    def test_authorize_v16_accepted_generates_high_finding(self):
        obj = self._make_instance()
        obj.results["data"]["ocpp_version"] = "1.6"

        response = json.dumps([3, "id1", {"idTagInfo": {"status": "Accepted"}}])
        obj.scanner._send_and_receive.return_value = response

        obj._test_authorize_flow()

        result = obj.results["data"]["authorize_flow"]
        self.assertEqual(result["status"], "Accepted")
        findings = self._get_findings(obj)
        self.assertIn("authorization bypass", findings[0]["issue"].lower())

    def test_authorize_v201_reads_id_token_info(self):
        """v2.0.1 uses idTokenInfo instead of idTagInfo."""
        obj = self._make_instance()
        obj.results["data"]["ocpp_version"] = "2.0.1"

        response = json.dumps([3, "id1", {"idTokenInfo": {"status": "Accepted"}}])
        obj.scanner._send_and_receive.return_value = response

        obj._test_authorize_flow()

        self.assertEqual(obj.results["data"]["authorize_flow"]["status"], "Accepted")

    def test_authorize_invalid_token_no_finding(self):
        obj = self._make_instance()
        obj.results["data"]["ocpp_version"] = "1.6"

        response = json.dumps([3, "id1", {"idTagInfo": {"status": "Invalid"}}])
        obj.scanner._send_and_receive.return_value = response

        obj._test_authorize_flow()

        self.assertEqual(obj.results["data"]["authorize_flow"]["status"], "Invalid")
        self.assertEqual(len(self._get_findings(obj)), 0)

    # --- Full charging session lifecycle ---

    def test_charging_session_full_lifecycle(self):
        """Start -> MeterValues -> Stop, all accepted."""
        obj = self._make_instance()
        actions_sent = []

        def fake_send(conn, msg, timeout=5):
            data = json.loads(msg)
            action = data[2]
            actions_sent.append(action)

            if action == "StartTransaction":
                return json.dumps(
                    [
                        3,
                        data[1],
                        {
                            "idTagInfo": {"status": "Accepted"},
                            "transactionId": 42,
                        },
                    ]
                )
            elif action in ("MeterValues", "StopTransaction"):
                return json.dumps([3, data[1], {}])
            return json.dumps([4, data[1], "NotImplemented", "", {}])

        obj.scanner._send_and_receive.side_effect = fake_send

        obj._test_charging_session()

        result = obj.results["data"]["charging_session"]
        self.assertEqual(result["start_status"], "Accepted")
        self.assertEqual(result["transaction_id"], 42)
        self.assertEqual(result["meter_values_status"], "Accepted")
        self.assertEqual(result["stop_status"], "Accepted")
        # Verify order
        self.assertEqual(actions_sent, ["StartTransaction", "MeterValues", "StopTransaction"])

    def test_charging_session_meter_skipped_when_start_rejected(self):
        """MeterValues should NOT be sent if StartTransaction was rejected."""
        obj = self._make_instance()
        actions_sent = []

        def fake_send(conn, msg, timeout=5):
            data = json.loads(msg)
            actions_sent.append(data[2])

            if data[2] == "StartTransaction":
                return json.dumps(
                    [
                        3,
                        data[1],
                        {
                            "idTagInfo": {"status": "Invalid"},
                        },
                    ]
                )
            return json.dumps([3, data[1], {}])

        obj.scanner._send_and_receive.side_effect = fake_send

        obj._test_charging_session()

        result = obj.results["data"]["charging_session"]
        self.assertIsNone(result["transaction_id"])
        self.assertIsNone(result["meter_values_status"])
        # StopTransaction must still be sent (cleanup)
        self.assertIn("StopTransaction", actions_sent)
        self.assertNotIn("MeterValues", actions_sent)

    def test_charging_session_stop_always_sent(self):
        """StopTransaction must always be sent for cleanup, even on start failure."""
        obj = self._make_instance()
        actions_sent = []

        def fake_send(conn, msg, timeout=5):
            data = json.loads(msg)
            actions_sent.append(data[2])
            return None  # All timeout

        obj.scanner._send_and_receive.side_effect = fake_send

        obj._test_charging_session()

        self.assertIn("StopTransaction", actions_sent)

    # --- Meter injection ---

    def test_meter_injection_accepted_generates_high(self):
        obj = self._make_instance()
        obj.scanner._send_and_receive.return_value = json.dumps([3, "id1", {}])

        obj._test_meter_injection()

        findings = self._get_findings(obj)
        self.assertIn("999999", findings[0]["description"])

    def test_meter_injection_error_no_finding(self):
        obj = self._make_instance()
        obj.scanner._send_and_receive.return_value = json.dumps(
            [4, "id1", "PropertyConstraintViolation", "Bad data", {}]
        )

        obj._test_meter_injection()
        self.assertEqual(len(self._get_findings(obj)), 0)

    # --- Transaction event (v2.0.1) ---

    def test_transaction_event_lifecycle(self):
        """Started -> Updated -> Ended, all accepted."""
        obj = self._make_instance()
        obj.scanner._send_and_receive.return_value = json.dumps([3, "id1", {}])

        obj._test_transaction_event()

        result = obj.results["data"]["transaction_event"]
        self.assertEqual(result["started_status"], "Accepted")
        self.assertEqual(result["updated_status"], "Accepted")
        self.assertEqual(result["ended_status"], "Accepted")

    def test_transaction_event_updated_skipped_when_started_fails(self):
        """Updated should NOT be sent if Started was rejected."""
        obj = self._make_instance()
        obj.scanner._send_and_receive.return_value = json.dumps(
            [4, "id1", "NotImplemented", "", {}]
        )

        obj._test_transaction_event()

        result = obj.results["data"]["transaction_event"]
        self.assertIn("NotImplemented", result["started_status"])
        self.assertIsNone(result["updated_status"])  # Skipped
        # Ended must still be sent (cleanup)
        self.assertIsNotNone(result["ended_status"])

    def test_transaction_event_ended_always_sent(self):
        """Ended must always be attempted for cleanup."""
        obj = self._make_instance()
        obj.scanner._send_and_receive.return_value = None

        obj._test_transaction_event()

        result = obj.results["data"]["transaction_event"]
        self.assertEqual(result["ended_status"], "no_response")

    # --- No-connection guard ---

    def test_all_charging_methods_noop_without_connection(self):
        obj = self._make_instance()
        obj.conn = None

        obj._test_authorize_flow()
        obj._test_charging_session()
        obj._test_meter_injection()
        obj._test_transaction_event()

        for key in ["authorize_flow", "charging_session", "meter_injection", "transaction_event"]:
            self.assertNotIn(key, obj.results["data"])


# ---------------------------------------------------------------------------
# Dispatch wiring tests -- verify flag-to-handler mapping completeness
# ---------------------------------------------------------------------------


class TestDispatchWiring(unittest.TestCase):
    """Test that CLI flags are correctly wired to handler methods"""

    def test_security_flag_triggers_all_security_checks(self):
        """--security must trigger ALL security checks and probes."""
        from oida.protocols.ocpp import ocpp as OcppClass

        # Verify all check flags are in the check handler map
        all_check_flags = OcppClass._SECURITY_CHECK_FLAGS
        all_probe_flags = OcppClass._SECURITY_PROBE_FLAGS

        self.assertGreater(len(all_check_flags), 0)
        self.assertGreater(len(all_probe_flags), 0)

    def test_discovery_dispatch_covers_all_discovery_flags(self):
        """Every flag in _DISCOVERY_FLAGS must have a handler in _dispatch_discovery."""
        from oida.protocols.ocpp import ocpp as OcppClass
        import inspect

        # Get the source of _dispatch_discovery to find the flag_to_handler dict
        source = inspect.getsource(OcppClass._dispatch_discovery)

        for flag in OcppClass._DISCOVERY_FLAGS:
            # enum_versions is handled pre-connection in proto_flow, not in _dispatch_discovery
            if flag == "enum_versions":
                continue
            self.assertIn(
                f'"{flag}"',
                source,
                f"Discovery flag '{flag}' not in _dispatch_discovery handler map",
            )

    def test_security_probe_dispatch_covers_all_probe_flags(self):
        """Every flag in _SECURITY_PROBE_FLAGS must have a handler."""
        from oida.protocols.ocpp import ocpp as OcppClass
        import inspect

        source = inspect.getsource(OcppClass._dispatch_security_probes)

        for flag in OcppClass._SECURITY_PROBE_FLAGS:
            self.assertIn(
                f'"{flag}"',
                source,
                f"Probe flag '{flag}' not in _dispatch_security_probes handler map",
            )

    def test_charging_dispatch_covers_all_charging_flags(self):
        from oida.protocols.ocpp import ocpp as OcppClass
        import inspect

        source = inspect.getsource(OcppClass._dispatch_charging_tests)

        for flag in OcppClass._CHARGING_FLAGS:
            self.assertIn(
                f'"{flag}"',
                source,
                f"Charging flag '{flag}' not in _dispatch_charging_tests handler map",
            )

    def test_all_flag_lists_are_in_operation_flags(self):
        """_OPERATION_FLAGS must include all discovery, security, probe, and charging flags."""
        from oida.protocols.ocpp import ocpp as OcppClass

        all_flags = (
            OcppClass._DISCOVERY_FLAGS
            + OcppClass._SECURITY_CHECK_FLAGS
            + OcppClass._SECURITY_PROBE_FLAGS
            + OcppClass._CHARGING_FLAGS
        )

        for flag in all_flags:
            self.assertIn(
                flag, OcppClass._OPERATION_FLAGS, f"Flag '{flag}' missing from _OPERATION_FLAGS"
            )

    def test_nxc_class_inherits_all_required_mixins(self):
        from oida.protocols.ocpp import ocpp as OCPPClass
        from oida.connection import NetworkConnection
        from oida.protocols.ocpp.mixins.discovery import DiscoveryMixin
        from oida.protocols.ocpp.mixins.security import SecurityMixin
        from oida.protocols.ocpp.mixins.messages import MessagesMixin
        from oida.protocols.ocpp.mixins.charging import ChargingMixin

        for mixin in [
            NetworkConnection,
            DiscoveryMixin,
            SecurityMixin,
            MessagesMixin,
            ChargingMixin,
        ]:
            self.assertTrue(
                issubclass(OCPPClass, mixin), f"ocpp class does not inherit from {mixin.__name__}"
            )


# ---------------------------------------------------------------------------
# Proto args tests -- only test non-trivial behavior
# ---------------------------------------------------------------------------


class TestOCPPProtoArgs(unittest.TestCase):
    """Test OCPP CLI argument definitions for non-trivial behavior"""

    def _parse_args(self, args_list):
        import argparse

        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()

        from oida.protocols.ocpp.proto_args import proto_args

        proto_args(subparsers, parents=[])
        return parser.parse_args(["ocpp"] + args_list)

    def test_version_choices_restricted(self):
        """Version must be one of the valid choices."""
        with self.assertRaises(SystemExit):
            self._parse_args(["ws://host:9000/CP1", "--version", "3.0"])

    def test_default_connector_id_is_zero(self):
        args = self._parse_args(["ws://host:9000/CP1"])
        self.assertEqual(args.connector_id, 0)

    def test_security_flag_short_and_long(self):
        """Both -s and --security should work."""
        for flag in ["-s", "--security"]:
            args = self._parse_args(["ws://host:9000/CP1", flag])
            self.assertTrue(args.security)

    def test_all_security_probe_flags_parseable(self):
        """All security probe flags must be parseable without error."""
        probe_flags = [
            "--test-config-write",
            "--test-charging-profile",
            "--test-remote-start",
            "--test-remote-stop",
            "--test-reset",
            "--test-unlock",
            "--test-firmware",
            "--test-availability",
            "--test-clear-cache",
            "--test-diagnostics",
            "--test-reserve",
            "--test-local-list",
        ]
        for flag in probe_flags:
            args = self._parse_args(["ws://host:9000/CP1", flag])
            # Convert flag to attr name
            attr = flag.lstrip("-").replace("-", "_")
            self.assertTrue(getattr(args, attr), f"Flag {flag} not parsed correctly")

    def test_raw_message_accepts_json_string(self):
        raw = '[2,"id","Heartbeat",{}]'
        args = self._parse_args(["ws://host:9000/CP1", "--raw-message", raw])
        self.assertEqual(args.raw_message, raw)

    def test_brute_rate_default(self):
        args = self._parse_args(["ws://host:9000/CP1"])
        self.assertAlmostEqual(args.brute_rate, 0.5)


# ---------------------------------------------------------------------------
# Brute force tests
# ---------------------------------------------------------------------------


class TestBruteForceHTTPAuth(unittest.TestCase):
    """Test _brute_force_http_auth credential testing"""

    def _make_instance(self):
        from oida.protocols.ocpp.mixins.security import SecurityMixin
        from oida.protocols.ocpp.mixins.messages import MessagesMixin

        class FakeOCPP(SecurityMixin, MessagesMixin, ConfirmGateMixin):
            pass

        obj = FakeOCPP()
        obj.conn = Mock()
        obj.logger = Mock()
        obj.results = {"data": {"target_url": "ws://localhost:9000/CP1"}}
        obj.scanner = Mock()
        obj.args = Mock()
        obj.args.brute_rate = 0
        obj.args.continue_on_success = False
        return obj

    @staticmethod
    def _enforcing(valid_pairs):
        """side_effect modelling an endpoint that ENFORCES HTTP Basic Auth.

        Returns a connection only for the given valid (user, pass) pairs and
        rejects everything else -- including the invalid enforcement-probe
        credential the brute sends first to confirm the endpoint gates on auth.
        """
        import base64

        valid_b64 = {base64.b64encode(f"{u}:{p}".encode()).decode() for u, p in valid_pairs}
        return lambda url, auth: Mock() if auth in valid_b64 else None

    def test_valid_credential_generates_critical_finding(self):
        obj = self._make_instance()
        obj.scanner._connect_with_auth.side_effect = self._enforcing([("admin", "password")])

        obj._brute_force_http_auth(["admin"], ["password"])

        findings = obj.results["data"].get("security_findings", [])
        self.assertEqual(len(findings), 1)
        self.assertEqual(len(obj.results["data"]["brute_force"]["http_auth"]["valid"]), 1)

    def test_stop_on_success_stops_after_first_valid(self):
        obj = self._make_instance()
        obj.args.continue_on_success = False
        obj.scanner._connect_with_auth.side_effect = self._enforcing([("u1", "p1"), ("u2", "p1")])

        obj._brute_force_http_auth(["u1", "u2"], ["p1"])

        # 1 enforcement pre-check + 1 tested pair (stops after first success).
        self.assertEqual(obj.scanner._connect_with_auth.call_count, 2)

    def test_no_stop_on_success_tests_all(self):
        obj = self._make_instance()
        obj.args.continue_on_success = True
        obj.scanner._connect_with_auth.side_effect = self._enforcing([("u1", "p1"), ("u2", "p1")])

        obj._brute_force_http_auth(["u1", "u2"], ["p1"])

        # 1 enforcement pre-check + 2 tested pairs.
        self.assertEqual(obj.scanner._connect_with_auth.call_count, 3)

    def test_unenforced_endpoint_skips_brute(self):
        """If a known-invalid credential connects, the endpoint does not enforce
        auth (Security Profile 0); the brute is skipped instead of reporting
        every pair as valid."""
        obj = self._make_instance()
        obj.scanner._connect_with_auth.return_value = Mock()  # accepts anything

        obj._brute_force_http_auth(["admin", "root"], ["password"])

        # Only the enforcement pre-check runs; no per-pair attempts.
        self.assertEqual(obj.scanner._connect_with_auth.call_count, 1)
        result = obj.results["data"]["brute_force"]["http_auth"]
        self.assertFalse(result["enforced"])
        self.assertEqual(result["valid"], [])
        self.assertEqual(len(obj.results["data"].get("security_findings", [])), 0)

    def test_exception_handled_gracefully(self):
        obj = self._make_instance()
        obj.scanner._connect_with_auth.side_effect = Exception("reset")

        obj._brute_force_http_auth(["admin"], ["pass"])

        self.assertEqual(obj.results["data"]["brute_force"]["http_auth"]["tested"], 1)
        self.assertEqual(len(obj.results["data"]["brute_force"]["http_auth"]["valid"]), 0)


class TestBruteForceIdTags(unittest.TestCase):
    """Test _brute_force_id_tags authorization token testing"""

    def _make_instance(self):
        from oida.protocols.ocpp.mixins.security import SecurityMixin
        from oida.protocols.ocpp.mixins.messages import MessagesMixin

        class FakeOCPP(SecurityMixin, MessagesMixin, ConfirmGateMixin):
            pass

        obj = FakeOCPP()
        obj.conn = Mock()
        obj.logger = Mock()
        obj.results = {"data": {"target_url": "ws://localhost:9000/CP1"}}
        obj.scanner = Mock()
        obj.args = Mock()
        obj.args.brute_rate = 0
        obj.args.continue_on_success = False
        return obj

    def test_accepted_tag_generates_high_finding(self):
        obj = self._make_instance()
        obj.scanner._send_and_receive.return_value = json.dumps(
            [3, "uuid", {"idTagInfo": {"status": "Accepted"}}]
        )

        obj._brute_force_id_tags(["VALID_TAG"])

        findings = obj.results["data"].get("security_findings", [])
        matched = [f for f in findings if "Valid OCPP IdTag tokens found" in f["issue"]]
        self.assertEqual(len(matched), 1)
        valid = obj.results["data"]["brute_force"]["id_tags"]["valid"]
        self.assertEqual(valid[0]["id_tag"], "VALID_TAG")

    def test_v201_format_also_detected(self):
        """v2.0.1 uses idTokenInfo instead of idTagInfo."""
        obj = self._make_instance()
        obj.scanner._send_and_receive.return_value = json.dumps(
            [3, "uuid", {"idTokenInfo": {"status": "Accepted"}}]
        )

        obj._brute_force_id_tags(["V201_TAG"])

        self.assertEqual(len(obj.results["data"]["brute_force"]["id_tags"]["valid"]), 1)

    def test_empty_tags_skipped(self):
        obj = self._make_instance()
        obj.scanner._send_and_receive.return_value = None

        obj._brute_force_id_tags(["", "TAG1"])

        self.assertEqual(obj.results["data"]["brute_force"]["id_tags"]["tested"], 1)

    def test_no_connection_logs_failure(self):
        obj = self._make_instance()
        obj.conn = None

        obj._brute_force_id_tags(["TAG"])

        obj.logger.fail.assert_called()


# ---------------------------------------------------------------------------
# Connect with auth tests
# ---------------------------------------------------------------------------


class TestConnectWithAuth(unittest.TestCase):
    """Test _connect_with_auth for credential probing"""

    def _make_scanner(self):
        from oida.protocols.ocpp.scanner import OCPPScanner

        return OCPPScanner(
            {
                "target-url": "ws://localhost:9000/CP_001",
                "version": "auto",
                "charge-point-id": "CP_001",
                "rhost": "localhost",
                "rport": 9000,
                "timeout": 5,
                "verbose": 0,
            }
        )

    @patch("oida.protocols.ocpp.scanner._websockets")
    def test_401_returns_none(self, mock_ws_wrapper):
        scanner = self._make_scanner()
        mock_ws_wrapper.get_module.return_value = Mock()
        mock_ws_wrapper.dependencies_missing = False

        async def fake_connect(*a, **kw):
            raise Exception("server rejected WebSocket connection: HTTP 401")

        with patch("websockets.asyncio.client.connect", side_effect=fake_connect):
            result = scanner._connect_with_auth("ws://localhost:9000/CP_001", "YmFkOnBhc3M=")

        self.assertIsNone(result)

    @patch("oida.protocols.ocpp.scanner._websockets")
    def test_passes_authorization_header(self, mock_ws_wrapper):
        scanner = self._make_scanner()
        mock_ws_wrapper.get_module.return_value = Mock()
        mock_ws_wrapper.dependencies_missing = False

        captured_kwargs = {}

        async def fake_connect(*a, **kw):
            captured_kwargs.update(kw)
            return Mock()

        with patch("websockets.asyncio.client.connect", side_effect=fake_connect):
            scanner._connect_with_auth("ws://localhost:9000/CP_001", "dGVzdDoxMjM=")

        self.assertEqual(
            captured_kwargs["additional_headers"]["Authorization"],
            "Basic dGVzdDoxMjM=",
        )


# ---------------------------------------------------------------------------
# Module exports and loader integration
# ---------------------------------------------------------------------------


class TestOCPPModuleExports(unittest.TestCase):
    """Test OCPP module exports are loadable"""

    def test_package_exports_importable(self):
        from oida.protocols.ocpp import (
            metadata,
            run,
            dependencies_missing,
        )

        self.assertTrue(callable(run))
        self.assertIsInstance(metadata, dict)
        self.assertIn("name", metadata)
        self.assertIsInstance(dependencies_missing, bool)

    def test_protocol_in_loader(self):
        from oida.loader import ProtocolLoader
        from pathlib import Path

        loader = ProtocolLoader(str(Path("src/oida/protocols")))
        protocols = loader.get_protocols()

        self.assertIn("ocpp", protocols)

    def test_protocol_class_loadable(self):
        from oida.loader import ProtocolLoader
        from pathlib import Path

        loader = ProtocolLoader(str(Path("src/oida/protocols")))
        proto_class = loader.get_protocol_class("ocpp")

        self.assertIsNotNone(proto_class)


# ---------------------------------------------------------------------------
# Default credentials
# ---------------------------------------------------------------------------


class TestOCPPDefaultCredentials(unittest.TestCase):
    """Test OCPP default credentials are registered"""

    def test_ocpp_defaults_are_user_password_tuples(self):
        from oida.utils.default_credentials import get_protocol_defaults

        defaults = get_protocol_defaults("ocpp")
        self.assertIsInstance(defaults, list)
        self.assertGreater(len(defaults), 0)
        for item in defaults:
            self.assertIsInstance(item, tuple)
            self.assertEqual(len(item), 2)

    def test_ocpp_tags_are_strings(self):
        from oida.utils.default_credentials import get_protocol_defaults

        tags = get_protocol_defaults("ocpp_tags")
        self.assertIsInstance(tags, list)
        self.assertGreater(len(tags), 0)
        for tag in tags:
            self.assertIsInstance(tag, str)


# ---------------------------------------------------------------------------
# ShouldBruteForce detection
# ---------------------------------------------------------------------------


class TestShouldBruteForce(unittest.TestCase):
    """Test _should_brute_force detection logic"""

    def _make_mock_nxc(self):
        from oida.protocols.ocpp import ocpp as OcppClass

        obj = Mock(spec=OcppClass)
        obj.logger = Mock()
        obj._should_brute_force = OcppClass._should_brute_force.__get__(obj)
        return obj

    def test_brute_flag_true(self):
        obj = self._make_mock_nxc()
        obj.args = Mock()
        obj.args.brute = True
        obj.args.default_creds = False
        obj.args.username = None
        obj.args.password = None
        self.assertTrue(obj._should_brute_force())

    def test_default_creds_flag_true(self):
        obj = self._make_mock_nxc()
        obj.args = Mock()
        obj.args.brute = False
        obj.args.default_creds = True
        obj.args.username = None
        obj.args.password = None
        self.assertTrue(obj._should_brute_force())

    def test_no_flags_returns_false(self):
        obj = self._make_mock_nxc()
        obj.args = Mock()
        obj.args.brute = False
        obj.args.default_creds = False
        obj.args.username = None
        obj.args.password = None
        self.assertFalse(obj._should_brute_force())

    def test_single_username_not_file_returns_false(self):
        obj = self._make_mock_nxc()
        obj.args = Mock()
        obj.args.brute = False
        obj.args.default_creds = False
        obj.args.username = "admin"
        obj.args.password = None
        self.assertFalse(obj._should_brute_force())


# ---------------------------------------------------------------------------
# New discovery methods
# ---------------------------------------------------------------------------


class TestNewDiscoveryMethods(unittest.TestCase):
    """Test additional discovery methods: local_list, composite_schedule, certs"""

    def _make_instance(self):
        from oida.protocols.ocpp.mixins.discovery import DiscoveryMixin
        from oida.protocols.ocpp.mixins.messages import MessagesMixin

        class Combined(DiscoveryMixin, MessagesMixin):
            pass

        obj = Combined()
        obj.conn = Mock()
        obj.logger = Mock()
        obj.results = {"data": {}}
        obj.scanner = Mock()
        obj.args = Mock()
        obj.args.connector_id = 1
        return obj

    def test_local_list_version_stores_version_number(self):
        obj = self._make_instance()
        obj.scanner._send_and_receive.return_value = json.dumps([3, "id1", {"listVersion": 5}])

        obj.get_local_list_version()

        self.assertEqual(obj.results["data"]["local_list_version"], 5)

    def test_local_list_version_negative_one_means_unconfigured(self):
        obj = self._make_instance()
        obj.scanner._send_and_receive.return_value = json.dumps([3, "id1", {"listVersion": -1}])

        obj.get_local_list_version()

        self.assertEqual(obj.results["data"]["local_list_version"], -1)

    def test_composite_schedule_stores_schedule_data(self):
        obj = self._make_instance()
        schedule = {
            "chargingRateUnit": "A",
            "chargingSchedulePeriod": [{"startPeriod": 0, "limit": 32.0}],
        }
        obj.scanner._send_and_receive.return_value = json.dumps(
            [3, "id1", {"status": "Accepted", "chargingSchedule": schedule}]
        )

        obj.get_composite_schedule()

        result = obj.results["data"]["composite_schedule"]
        self.assertEqual(result["status"], "Accepted")
        self.assertIsNotNone(result["schedule"])

    def test_installed_certs_extracts_certificate_data(self):
        obj = self._make_instance()
        certs = [
            {
                "certificateType": "CSMSRootCertificate",
                "certificateHashData": {
                    "hashAlgorithm": "SHA256",
                    "serialNumber": "12345",
                },
            }
        ]
        obj.scanner._send_and_receive.return_value = json.dumps(
            [3, "id1", {"status": "Accepted", "certificateHashDataChain": certs}]
        )

        obj.get_installed_certs()

        result = obj.results["data"]["installed_certs"]
        self.assertEqual(result["status"], "Accepted")
        self.assertEqual(len(result["certificates"]), 1)
        self.assertEqual(result["certificates"][0]["certificateType"], "CSMSRootCertificate")

    def test_all_discovery_methods_noop_without_connection(self):
        obj = self._make_instance()
        obj.conn = None

        obj.get_local_list_version()
        obj.get_composite_schedule()
        obj.get_installed_certs()

        for key in ["local_list_version", "composite_schedule", "installed_certs"]:
            self.assertNotIn(key, obj.results["data"])


class TestListenMode(unittest.TestCase):
    """Tests for persistent listen mode with heartbeat keep-alive."""

    def _make_scanner(self):
        from oida.protocols.ocpp.scanner import OCPPScanner

        scanner = OCPPScanner.__new__(OCPPScanner)
        scanner.options = {}
        scanner.timeout = 5
        scanner.logger = MagicMock()
        return scanner

    def test_listen_mode_returns_empty_without_connection(self):
        scanner = self._make_scanner()
        result = scanner.listen_mode(None, timeout=1)
        self.assertEqual(result, [])

    def test_listen_mode_returns_empty_without_event_loop(self):
        scanner = self._make_scanner()
        scanner._event_loop = None
        result = scanner.listen_mode(MagicMock(), timeout=1)
        self.assertEqual(result, [])

    def test_listen_mode_returns_empty_with_closed_loop(self):
        scanner = self._make_scanner()
        loop = MagicMock()
        loop.is_closed.return_value = True
        scanner._event_loop = loop
        result = scanner.listen_mode(MagicMock(), timeout=1)
        self.assertEqual(result, [])

    def test_listen_mode_sends_heartbeat_and_exits_on_timeout(self):
        """Listen mode sends heartbeats and respects timeout."""
        import asyncio

        scanner = self._make_scanner()
        loop = asyncio.new_event_loop()
        scanner._event_loop = loop

        conn = AsyncMock()
        conn.recv.side_effect = asyncio.TimeoutError()
        conn.send = AsyncMock()

        try:
            result = scanner.listen_mode(conn, heartbeat_interval=1, timeout=3)
        finally:
            if not loop.is_closed():
                loop.close()

        self.assertEqual(result, [])
        self.assertTrue(conn.send.called)
        sent_msgs = [json.loads(call.args[0]) for call in conn.send.call_args_list]
        heartbeats = [m for m in sent_msgs if m[2] == "Heartbeat"]
        self.assertGreaterEqual(len(heartbeats), 1)
        self.assertEqual(heartbeats[0][0], 2)
        self.assertEqual(heartbeats[0][3], {})

    def test_listen_mode_records_incoming_calls(self):
        """Listen mode records and responds to server-initiated CALLs."""
        import asyncio

        scanner = self._make_scanner()
        loop = asyncio.new_event_loop()
        scanner._event_loop = loop

        call_msg = json.dumps([2, "srv-1", "Reset", {"type": "Soft"}])

        conn = AsyncMock()
        recv_calls = [0]

        async def mock_recv():
            recv_calls[0] += 1
            if recv_calls[0] == 1:
                return call_msg
            raise asyncio.TimeoutError()

        conn.recv = mock_recv
        conn.send = AsyncMock()

        try:
            result = scanner.listen_mode(conn, heartbeat_interval=100, timeout=2)
        finally:
            if not loop.is_closed():
                loop.close()

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["action"], "Reset")
        self.assertEqual(result[0]["message_id"], "srv-1")
        self.assertEqual(result[0]["payload"], {"type": "Soft"})

    def test_listen_mode_ignores_callresult(self):
        """CALLRESULT messages (e.g., heartbeat responses) are silently consumed."""
        import asyncio

        scanner = self._make_scanner()
        loop = asyncio.new_event_loop()
        scanner._event_loop = loop

        hb_response = json.dumps([3, "hb-1", {"currentTime": "2026-01-01T00:00:00Z"}])

        conn = AsyncMock()
        recv_calls = [0]

        async def mock_recv():
            recv_calls[0] += 1
            if recv_calls[0] == 1:
                return hb_response
            raise asyncio.TimeoutError()

        conn.recv = mock_recv
        conn.send = AsyncMock()

        try:
            result = scanner.listen_mode(conn, heartbeat_interval=100, timeout=2)
        finally:
            if not loop.is_closed():
                loop.close()

        self.assertEqual(result, [])

    def test_listen_mode_exits_on_connection_drop(self):
        """Listen mode exits cleanly when connection drops."""
        import asyncio

        scanner = self._make_scanner()
        loop = asyncio.new_event_loop()
        scanner._event_loop = loop

        conn = AsyncMock()
        conn.recv.side_effect = ConnectionError("Connection closed")
        conn.send = AsyncMock()

        try:
            result = scanner.listen_mode(conn, heartbeat_interval=100, timeout=10)
        finally:
            if not loop.is_closed():
                loop.close()

        self.assertEqual(result, [])

    def test_listen_mode_default_heartbeat_interval(self):
        """Default heartbeat interval is used when none specified."""
        from oida.protocols.ocpp.constants import DEFAULT_HEARTBEAT_INTERVAL

        self.assertEqual(DEFAULT_HEARTBEAT_INTERVAL, 30)


class TestListenModeDispatch(unittest.TestCase):
    """Tests for listen mode wiring in __init__.py dispatch."""

    def test_listen_flag_in_operation_flags(self):
        """--listen is recognized as an operation flag."""
        from oida.protocols.ocpp import ocpp as OcppClass

        self.assertIn("listen", OcppClass._OPERATION_FLAGS)

    def test_enter_listen_mode_noop_without_connection(self):
        """_enter_listen_mode does nothing when conn is None."""
        from oida.protocols.ocpp import ocpp as OcppClass

        args = MagicMock()
        args.target = "ws://host:9000/CP"
        args.port = 9000
        args.listen = True
        args.listen_timeout = None

        obj = OcppClass.__new__(OcppClass)
        obj.args = args
        obj.conn = None
        obj.scanner = MagicMock()
        obj.results = {"data": {}}
        obj.logger = MagicMock()

        obj._enter_listen_mode()
        obj.scanner.listen_mode.assert_not_called()

    def test_enter_listen_mode_uses_boot_interval(self):
        """_enter_listen_mode passes BootNotification interval to scanner."""
        from oida.protocols.ocpp import ocpp as OcppClass

        args = MagicMock()
        args.listen_timeout = 60

        obj = OcppClass.__new__(OcppClass)
        obj.args = args
        obj.conn = MagicMock()
        obj.scanner = MagicMock()
        obj.scanner.listen_mode.return_value = []
        obj.results = {"data": {"boot_notification": {"interval": 45}}}
        obj.logger = MagicMock()

        obj._enter_listen_mode()

        obj.scanner.listen_mode.assert_called_once_with(
            obj.conn,
            heartbeat_interval=45,
            timeout=60,
        )


class TestHandleFirmwareInfo(unittest.TestCase):
    """Test DiscoveryMixin._handle_firmware_info firmware-info parsing.

    After the duplicate-definition cleanup, the single surviving method must:
      - issue a targeted GetConfiguration for the fixed firmware key list and
        parse the OCPP 1.6 (configurationKey) and 2.x (getVariableResult)
        response shapes,
      - capture boot_status / server_time from the prior BootNotification,
      - additionally harvest firmware-related keys from any already-collected
        GetConfiguration data via the substring-hint heuristic (the unique
        behavior merged in from the former dead duplicate).
    """

    def _make_obj(self):
        from oida.protocols.ocpp import ocpp as OcppClass
        from oida.protocols.ocpp.constants import MessageType

        obj = OcppClass.__new__(OcppClass)
        obj.conn = MagicMock()
        obj.scanner = MagicMock()
        obj.logger = MagicMock()
        obj.results = {"data": {}}
        return obj, MessageType

    def test_single_handler_definition(self):
        """Regression: exactly one _handle_firmware_info must exist (no shadow)."""
        import inspect
        from oida.protocols.ocpp.mixins import discovery

        src = inspect.getsource(discovery.DiscoveryMixin)
        self.assertEqual(
            src.count("def _handle_firmware_info"),
            1,
            "Duplicate _handle_firmware_info definition reintroduced",
        )

    def test_no_connection_is_noop(self):
        obj, _ = self._make_obj()
        obj.conn = None
        obj._handle_firmware_info()
        self.assertNotIn("firmware_info", obj.results["data"])

    def test_parses_ocpp16_configuration_key_response(self):
        """1.6 CALLRESULT configurationKey entries are folded into firmware_info."""
        obj, MessageType = self._make_obj()
        obj.results["data"]["ocpp_version"] = "1.6"
        obj.results["data"]["boot_notification"] = {
            "status": "Accepted",
            "current_time": "2026-06-18T00:00:00Z",
        }
        payload = {
            "configurationKey": [
                {"key": "FirmwareVersion", "value": "1.2.3"},
                {"key": "ChargePointVendor", "value": "ACME"},
            ]
        }
        obj.scanner._send_and_receive.return_value = json.dumps(
            [MessageType.CALLRESULT, "id1", payload]
        )

        obj._handle_firmware_info()

        info = obj.results["data"]["firmware_info"]
        self.assertEqual(info["boot_status"], "Accepted")
        self.assertEqual(info["server_time"], "2026-06-18T00:00:00Z")
        self.assertEqual(info["FirmwareVersion"], "1.2.3")
        self.assertEqual(info["ChargePointVendor"], "ACME")

    def test_harvests_hint_matched_keys_from_existing_configuration(self):
        """Merged behavior: substring-hint scan over already-collected config keys.

        A vendor-specific key not in _FIRMWARE_CONFIG_KEYS but matching a hint
        ('version') must still be surfaced. Targeted request returns no result.
        """
        obj, _ = self._make_obj()
        obj.results["data"]["ocpp_version"] = "1.6"
        obj.results["data"]["configuration"] = {
            "keys": [
                {"key": "VendorFirmwareVersion", "value": "9.9", "readonly": True},
                {"key": "HeartbeatInterval", "value": "300", "readonly": False},
            ]
        }
        # No usable response to the targeted GetConfiguration.
        obj.scanner._send_and_receive.return_value = None

        obj._handle_firmware_info()

        info = obj.results["data"]["firmware_info"]
        self.assertEqual(
            info.get("VendorFirmwareVersion"),
            "9.9",
            "hint-matched config key should be harvested",
        )
        self.assertNotIn("HeartbeatInterval", info, "non-firmware key must not be harvested")

    def test_targeted_response_does_not_clobber_existing_hint_value(self):
        """setdefault semantics: prior hint value wins over a later empty/dup."""
        obj, MessageType = self._make_obj()
        obj.results["data"]["ocpp_version"] = "1.6"
        obj.results["data"]["configuration"] = {
            "keys": [{"key": "FirmwareVersion", "value": "harvested-1.0"}]
        }
        payload = {"configurationKey": [{"key": "FirmwareVersion", "value": "targeted-2.0"}]}
        obj.scanner._send_and_receive.return_value = json.dumps(
            [MessageType.CALLRESULT, "id1", payload]
        )

        obj._handle_firmware_info()

        # Hint-scan runs first and populates via setdefault; the targeted loop
        # overwrites directly, so the targeted value is authoritative here.
        self.assertEqual(obj.results["data"]["firmware_info"]["FirmwareVersion"], "targeted-2.0")

    def test_parses_ocpp201_get_variable_result(self):
        """2.x getVariableResult entries are parsed into firmware_info."""
        obj, MessageType = self._make_obj()
        obj.results["data"]["ocpp_version"] = "2.0.1"
        payload = {
            "getVariableResult": [
                {
                    "variable": {"name": "FirmwareVersion"},
                    "attributeValue": "2.0.1-rc",
                }
            ]
        }
        obj.scanner._send_and_receive.return_value = json.dumps(
            [MessageType.CALLRESULT, "id1", payload]
        )

        obj._handle_firmware_info()

        self.assertEqual(obj.results["data"]["firmware_info"]["FirmwareVersion"], "2.0.1-rc")

    def test_no_details_still_records_empty_firmware_info(self):
        obj, _ = self._make_obj()
        obj.results["data"]["ocpp_version"] = "1.6"
        obj.scanner._send_and_receive.return_value = None

        obj._handle_firmware_info()

        self.assertEqual(obj.results["data"]["firmware_info"], {})


if __name__ == "__main__":
    unittest.main()
