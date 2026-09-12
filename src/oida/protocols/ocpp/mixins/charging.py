"""
OCPP Charging Flow Mixin

Provides CP-initiated charging session test methods for the NXC-style
OCPP connection class. Tests authorization bypass, full charging session
flow, meter value injection, and OCPP 2.0.1 TransactionEvent flow.

All probes use clearly fake/safe values (FAKE_ID_TAG, SAFE_TRANSACTION_ID, etc.)
to avoid unintended side effects on real infrastructure.
"""

import datetime

from ..constants import (
    MessageType,
    FAKE_ID_TAG,
    SAFE_TRANSACTION_ID,
    SAFE_CONNECTOR_ID,
    SAFE_METER_START,
    SAFE_METER_STOP,
)


class ChargingMixin:
    """Mixin for OCPP charging session security testing"""

    def _test_authorize_flow(self):
        """
        Test if the CSMS accepts arbitrary idTags (authorization bypass detection).

        Sends an Authorize CALL with the clearly fake OIDA test tag.
        If the CSMS returns Accepted, this indicates missing authorization
        validation -- any badge/token would be accepted.

        Safety: Uses FAKE_ID_TAG which will never match a real auth list entry.
        """
        if not self.conn:
            return

        self.logger.display("[Charging] Authorization bypass test")

        version = self.results["data"].get("ocpp_version", "1.6") or "1.6"
        self.logger.debug(f"Authorize bypass test: idTag={FAKE_ID_TAG}, version={version}")
        result_data = {"id_tag": FAKE_ID_TAG, "status": None}

        try:
            auth_msg = self._build_authorize(FAKE_ID_TAG, version=version)
            response = self.scanner._send_and_receive(self.conn, auth_msg, timeout=5)

            if response is None:
                self.logger.display("  Authorize: no response")
                result_data["status"] = "no_response"
            else:
                msg_type, _, payload = self._parse_message(response)

                if msg_type == MessageType.CALLRESULT:
                    if version.startswith("2."):
                        id_tag_info = payload.get("idTokenInfo", {})
                    else:
                        id_tag_info = payload.get("idTagInfo", {})

                    status = id_tag_info.get("status", "Unknown")
                    result_data["status"] = status
                    self.logger.debug(f"Authorize response: status={status}")

                    if status == "Accepted":
                        self.logger.warning(
                            f"  Authorize({FAKE_ID_TAG}): ACCEPTED (any idTag accepted)"
                        )
                        self._add_finding(
                            "Authorization bypass: fake idTag accepted",
                            f"Authorize with fake idTag '{FAKE_ID_TAG}' was accepted. "
                            "CSMS does not validate authorization tokens.",
                        )
                    elif status == "Invalid":
                        self.logger.display(
                            f"  Authorize({FAKE_ID_TAG}): Invalid (good - token rejected)"
                        )
                    else:
                        self.logger.display(f"  Authorize({FAKE_ID_TAG}): {status}")

                elif msg_type == MessageType.CALLERROR:
                    error_code = payload.get("error_code", "")
                    result_data["status"] = f"error:{error_code}"
                    self.logger.display(f"  Authorize: {error_code}")

        except Exception as e:
            self.logger.debug(f"Authorize flow failed: {e}")
            result_data["status"] = f"exception:{e}"

        self.results["data"]["authorize_flow"] = result_data

    def _test_charging_session(self):
        """
        Test full charging session flow: StartTransaction -> MeterValues -> StopTransaction.

        This is an OCPP 1.6 flow that tests whether the CSMS accepts a full
        charge session from an unauthenticated scanner. Each step is logged
        and the transaction is always stopped (cleanup) even if start fails.

        Safety:
        - Uses FAKE_ID_TAG for authorization
        - Uses SAFE_CONNECTOR_ID (connector 1)
        - MeterValues report 0 Wh (no actual energy)
        - StopTransaction always sent to clean up
        """
        if not self.conn:
            return

        self.logger.display("[Charging] Full session flow test (OCPP 1.6)")

        result_data = {
            "start_status": None,
            "transaction_id": None,
            "meter_values_status": None,
            "stop_status": None,
        }

        connector_id = getattr(self.args, "connector_id", SAFE_CONNECTOR_ID) or SAFE_CONNECTOR_ID
        self.logger.debug(f"Charging session test: connector={connector_id}, idTag={FAKE_ID_TAG}")
        transaction_id = None

        # Step 1: StartTransaction
        self.logger.debug("Step 1: StartTransaction")
        try:
            start_msg = self._build_start_transaction(
                connector_id=connector_id,
                id_tag=FAKE_ID_TAG,
                meter_start=SAFE_METER_START,
            )

            response = self.scanner._send_and_receive(self.conn, start_msg, timeout=5)

            if response is None:
                self.logger.display("  StartTransaction: no response")
                result_data["start_status"] = "no_response"
            else:
                msg_type, _, payload = self._parse_message(response)

                if msg_type == MessageType.CALLRESULT:
                    id_tag_info = payload.get("idTagInfo", {})
                    status = id_tag_info.get("status", "Unknown")
                    transaction_id = payload.get("transactionId")
                    result_data["start_status"] = status
                    result_data["transaction_id"] = transaction_id

                    if status == "Accepted":
                        self.logger.warning(f"  StartTransaction: ACCEPTED (txId={transaction_id})")
                        self._add_finding(
                            "Unauthorized charging session started",
                            f"StartTransaction with fake idTag was accepted "
                            f"(transactionId={transaction_id}). "
                            "Unauthorized energy consumption possible.",
                        )
                    else:
                        self.logger.display(f"  StartTransaction: {status}")

                elif msg_type == MessageType.CALLERROR:
                    error_code = payload.get("error_code", "")
                    result_data["start_status"] = f"error:{error_code}"
                    self.logger.display(f"  StartTransaction: {error_code}")

        except Exception as e:
            self.logger.debug(f"StartTransaction failed: {e}")
            result_data["start_status"] = f"exception:{e}"

        # Step 2: MeterValues (only if transaction started)
        if transaction_id is not None:
            self.logger.debug(f"Step 2: MeterValues (txId={transaction_id})")
            try:
                meter_msg = self._build_meter_values(
                    connector_id=connector_id,
                    transaction_id=transaction_id,
                )

                response = self.scanner._send_and_receive(self.conn, meter_msg, timeout=5)

                if response is None:
                    result_data["meter_values_status"] = "no_response"
                else:
                    msg_type, _, payload = self._parse_message(response)

                    if msg_type == MessageType.CALLRESULT:
                        result_data["meter_values_status"] = "Accepted"
                        self.logger.display("  MeterValues: Accepted")
                    elif msg_type == MessageType.CALLERROR:
                        error_code = payload.get("error_code", "")
                        result_data["meter_values_status"] = f"error:{error_code}"
                        self.logger.display(f"  MeterValues: {error_code}")

            except Exception as e:
                self.logger.debug(f"MeterValues failed: {e}")
                result_data["meter_values_status"] = f"exception:{e}"

        # Step 3: StopTransaction (always attempt cleanup)
        tx_id_to_stop = transaction_id if transaction_id is not None else SAFE_TRANSACTION_ID
        self.logger.debug(f"Step 3: StopTransaction (txId={tx_id_to_stop})")
        try:
            stop_msg = self._build_stop_transaction(
                transaction_id=tx_id_to_stop,
                id_tag=FAKE_ID_TAG,
                meter_stop=SAFE_METER_STOP,
                reason="Local",
            )

            response = self.scanner._send_and_receive(self.conn, stop_msg, timeout=5)

            if response is None:
                result_data["stop_status"] = "no_response"
                self.logger.display("  StopTransaction: no response")
            else:
                msg_type, _, payload = self._parse_message(response)

                if msg_type == MessageType.CALLRESULT:
                    result_data["stop_status"] = "Accepted"
                    self.logger.display("  StopTransaction: Accepted (cleanup)")
                elif msg_type == MessageType.CALLERROR:
                    error_code = payload.get("error_code", "")
                    result_data["stop_status"] = f"error:{error_code}"
                    self.logger.display(f"  StopTransaction: {error_code}")

        except Exception as e:
            self.logger.debug(f"StopTransaction failed: {e}")
            result_data["stop_status"] = f"exception:{e}"

        self.results["data"]["charging_session"] = result_data

    def _test_meter_injection(self):
        """
        Test meter value injection by sending crafted MeterValues.

        Sends MeterValues with a high energy reading to test whether the CSMS
        accepts arbitrary meter data without validation. If accepted, this
        represents a billing integrity risk -- an attacker could forge
        energy consumption data.

        Safety: Uses SAFE_TRANSACTION_ID (0) which should not match any active
        transaction. The injected values are clearly fake.
        """
        if not self.conn:
            return

        self.logger.display("[Charging] Meter value injection test")

        connector_id = getattr(self.args, "connector_id", SAFE_CONNECTOR_ID) or SAFE_CONNECTOR_ID
        self.logger.debug(
            f"Meter injection test: connector={connector_id}, txId={SAFE_TRANSACTION_ID}"
        )
        result_data = {"status": None, "connector_id": connector_id}

        now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")

        # Craft MeterValues with an obviously inflated energy reading
        crafted_values = [
            {
                "timestamp": now,
                "sampledValue": [
                    {
                        "value": "999999",
                        "measurand": "Energy.Active.Import.Register",
                        "unit": "Wh",
                        "context": "Sample.Periodic",
                    },
                    {
                        "value": "99999",
                        "measurand": "Power.Active.Import",
                        "unit": "W",
                    },
                ],
            },
        ]

        try:
            meter_msg = self._build_meter_values(
                connector_id=connector_id,
                transaction_id=SAFE_TRANSACTION_ID,
                meter_value_list=crafted_values,
            )

            response = self.scanner._send_and_receive(self.conn, meter_msg, timeout=5)

            if response is None:
                self.logger.display("  MeterValues injection: no response")
                result_data["status"] = "no_response"
            else:
                msg_type, _, payload = self._parse_message(response)

                if msg_type == MessageType.CALLRESULT:
                    result_data["status"] = "Accepted"
                    self.logger.warning(
                        "  MeterValues injection: ACCEPTED (crafted meter values accepted)"
                    )
                    self._add_finding(
                        "Meter value injection accepted",
                        "MeterValues with crafted energy readings (999999 Wh) were "
                        "accepted without validation. Billing fraud is possible.",
                    )

                elif msg_type == MessageType.CALLERROR:
                    error_code = payload.get("error_code", "")
                    result_data["status"] = f"error:{error_code}"
                    self.logger.display(f"  MeterValues injection: {error_code}")

        except Exception as e:
            self.logger.debug(f"MeterValues injection failed: {e}")
            result_data["status"] = f"exception:{e}"

        self.results["data"]["meter_injection"] = result_data

    def _test_transaction_event(self):
        """
        Test OCPP 2.0.1 TransactionEvent flow.

        Sends Started -> Updated -> Ended TransactionEvent messages to test
        whether the CSMS processes transaction lifecycle events from an
        unauthenticated scanner.

        This is the 2.0.1 equivalent of _test_charging_session().

        Safety: Uses clearly fake transaction ID and minimal payloads.
        """
        if not self.conn:
            return

        self.logger.display("[Charging] TransactionEvent test (OCPP 2.0.1)")
        self.logger.debug("TransactionEvent test: Started -> Updated -> Ended")

        result_data = {
            "started_status": None,
            "updated_status": None,
            "ended_status": None,
        }

        tx_info = {"transactionId": "OIDA-TX-PROBE-001"}

        # Step 1: TransactionEvent Started
        self.logger.debug("Step 1: TransactionEvent(Started)")
        try:
            started_msg = self._build_transaction_event(
                event_type="Started",
                trigger_reason="Authorized",
                seq_no=0,
                transaction_info=tx_info,
            )

            response = self.scanner._send_and_receive(self.conn, started_msg, timeout=5)

            if response is None:
                result_data["started_status"] = "no_response"
                self.logger.display("  TransactionEvent(Started): no response")
            else:
                msg_type, _, payload = self._parse_message(response)

                if msg_type == MessageType.CALLRESULT:
                    result_data["started_status"] = "Accepted"
                    self.logger.warning("  TransactionEvent(Started): ACCEPTED")
                    self._add_finding(
                        "Unauthorized TransactionEvent(Started) accepted",
                        "OCPP 2.0.1 TransactionEvent with Started type was accepted "
                        "from unauthenticated scanner.",
                    )

                elif msg_type == MessageType.CALLERROR:
                    error_code = payload.get("error_code", "")
                    result_data["started_status"] = f"error:{error_code}"
                    self.logger.display(f"  TransactionEvent(Started): {error_code}")

        except Exception as e:
            self.logger.debug(f"TransactionEvent(Started) failed: {e}")
            result_data["started_status"] = f"exception:{e}"

        # Step 2: TransactionEvent Updated (only if Started succeeded)
        if result_data["started_status"] == "Accepted":
            self.logger.debug("Step 2: TransactionEvent(Updated)")
            try:
                updated_msg = self._build_transaction_event(
                    event_type="Updated",
                    trigger_reason="MeterValuePeriodic",
                    seq_no=1,
                    transaction_info=tx_info,
                )

                response = self.scanner._send_and_receive(self.conn, updated_msg, timeout=5)

                if response is None:
                    result_data["updated_status"] = "no_response"
                else:
                    msg_type, _, payload = self._parse_message(response)

                    if msg_type == MessageType.CALLRESULT:
                        result_data["updated_status"] = "Accepted"
                        self.logger.display("  TransactionEvent(Updated): Accepted")
                    elif msg_type == MessageType.CALLERROR:
                        error_code = payload.get("error_code", "")
                        result_data["updated_status"] = f"error:{error_code}"

            except Exception as e:
                self.logger.debug(f"TransactionEvent(Updated) failed: {e}")
                result_data["updated_status"] = f"exception:{e}"

        # Step 3: TransactionEvent Ended (always attempt cleanup)
        self.logger.debug("Step 3: TransactionEvent(Ended) - cleanup")
        try:
            ended_msg = self._build_transaction_event(
                event_type="Ended",
                trigger_reason="StopAuthorized",
                seq_no=2,
                transaction_info=tx_info,
            )

            response = self.scanner._send_and_receive(self.conn, ended_msg, timeout=5)

            if response is None:
                result_data["ended_status"] = "no_response"
                self.logger.display("  TransactionEvent(Ended): no response")
            else:
                msg_type, _, payload = self._parse_message(response)

                if msg_type == MessageType.CALLRESULT:
                    result_data["ended_status"] = "Accepted"
                    self.logger.display("  TransactionEvent(Ended): Accepted (cleanup)")
                elif msg_type == MessageType.CALLERROR:
                    error_code = payload.get("error_code", "")
                    result_data["ended_status"] = f"error:{error_code}"
                    self.logger.display(f"  TransactionEvent(Ended): {error_code}")

        except Exception as e:
            self.logger.debug(f"TransactionEvent(Ended) failed: {e}")
            result_data["ended_status"] = f"exception:{e}"

        self.results["data"]["transaction_event"] = result_data
