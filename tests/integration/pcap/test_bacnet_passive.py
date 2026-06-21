"""Integration tests for BACnet passive listener in EK mode.

Tests cover the 9 T1 tshark fields added in the field-coverage improvement:
  1. bacapp.objectIdentifier  - combined object type+instance composite
  2. bacapp.invoke_id         - request/response correlation
  3. bacapp.error_class       - error classification (Error PDU)
  4. bacapp.error_code        - specific error code (Error PDU)
  5. bacapp.reject_reason     - reject reason (Reject PDU)
  6. bacapp.abort_reason      - abort reason (Abort PDU)
  7. bacapp.sequence_number   - segmented transfer tracking
  8. bacapp.deviceIdentifier  - BACnet device identity
  9. bacapp.processId         - process identifier (subscriptions)
"""

import pytest

from .conftest import _run_listener_test

pytestmark = [pytest.mark.integration]


class TestBACnetPassiveEK:
    """BACnet-specific tests beyond the parametrized quality suite."""

    def test_bacnet_sessions_and_services(self):
        listener, devices, result = _run_listener_test(
            "bacnet",
            "BACnetPassiveListener",
            "bacapp",
            "bacnet/cisagov_bacnet_example.pcap",
            expect_details=["service"],
        )

        # A1: sessions populated
        assert len(listener.sessions) >= 1, (
            f"Expected >= 1 BACnet session, got {len(listener.sessions)}"
        )

        # A2: session has services
        for session in listener.sessions.values():
            assert session.services, "Session has no services"

        # A3: passive_data on at least one device
        has_data = any(
            hasattr(d, "bacnet_passive_data") and d.bacnet_passive_data for d in devices.values()
        )
        assert has_data, "No device has bacnet_passive_data"

        # A4: harvest returns a dict (tables are now built centrally by scanner)
        assert isinstance(result, dict)


class TestBACnetInvokeId:
    """T1 gap: bacapp.invoke_id -- request/response correlation."""

    def test_invoke_id_extracted(self):
        """invoke_id appears in interaction details for confirmed services."""
        listener, devices, result = _run_listener_test(
            "bacnet",
            "BACnetPassiveListener",
            "bacapp",
            "bacnet/cisagov_bacnet_example.pcap",
            expect_details=["service"],
        )

        # At least one interaction should have invoke_id
        has_invoke = any("invoke_id" in ix.details for ix in listener.interactions)
        assert has_invoke, (
            "No interaction has 'invoke_id' in details; "
            f"sample: {listener.interactions[0].details if listener.interactions else 'none'}"
        )

        # invoke_id should be an integer
        for ix in listener.interactions:
            if "invoke_id" in ix.details:
                assert isinstance(ix.details["invoke_id"], int), (
                    f"invoke_id should be int, got {type(ix.details['invoke_id'])}"
                )
                break


class TestBACnetObjectIdentifier:
    """T1 gap: bacapp.objectIdentifier -- combined object ID."""

    def test_object_identifier_extracted(self):
        """objectIdentifier appears in interaction details."""
        listener, devices, result = _run_listener_test(
            "bacnet",
            "BACnetPassiveListener",
            "bacapp",
            "bacnet/cisagov_bacnet_example.pcap",
            expect_details=["service"],
        )

        has_oid = any("object_identifier" in ix.details for ix in listener.interactions)
        assert has_oid, (
            "No interaction has 'object_identifier' in details; "
            "bacapp.objectIdentifier extraction may be broken"
        )

        for ix in listener.interactions:
            if "object_identifier" in ix.details:
                assert isinstance(ix.details["object_identifier"], int), (
                    f"object_identifier should be int, got {type(ix.details['object_identifier'])}"
                )
                break


class TestBACnetErrorFields:
    """T1 gaps: bacapp.error_class and bacapp.error_code."""

    def test_error_class_and_code_extracted(self):
        """Error PDUs (type=5) have error_class and error_code in details."""
        listener, devices, result = _run_listener_test(
            "bacnet",
            "BACnetPassiveListener",
            "bacapp",
            "bacnet/cisagov_bacnet_errors.pcap",
            expect_details=["service"],
        )

        # Find error interactions
        error_ixns = [ix for ix in listener.interactions if ix.details.get("service") == "Error"]
        assert len(error_ixns) >= 1, (
            "Expected at least 1 Error interaction in cisagov_bacnet_errors.pcap"
        )

        # Check error_class
        has_class = any("error_class" in ix.details for ix in error_ixns)
        assert has_class, "No Error interaction has 'error_class' in details"

        # Check error_code
        has_code = any("error_code" in ix.details for ix in error_ixns)
        assert has_code, "No Error interaction has 'error_code' in details"

        # Check human-readable names are populated
        for ix in error_ixns:
            if "error_class" in ix.details:
                assert "error_class_name" in ix.details, (
                    "error_class present but error_class_name missing"
                )
                assert isinstance(ix.details["error_class_name"], str)
                assert ix.details["error_class_name"], "error_class_name is empty"
                break

        for ix in error_ixns:
            if "error_code" in ix.details:
                assert "error_code_name" in ix.details, (
                    "error_code present but error_code_name missing"
                )
                assert isinstance(ix.details["error_code_name"], str)
                assert ix.details["error_code_name"], "error_code_name is empty"
                break

    def test_error_summary_includes_details(self):
        """Error interaction summary includes class/code names."""
        listener, _devices, _result = _run_listener_test(
            "bacnet",
            "BACnetPassiveListener",
            "bacapp",
            "bacnet/cisagov_bacnet_errors.pcap",
            expect_details=["service"],
        )

        error_ixns = [
            ix
            for ix in listener.interactions
            if ix.details.get("service") == "Error" and "error_class" in ix.details
        ]
        assert error_ixns, "No error interactions with error_class found"

        # Summary should mention the error class/code name
        ix = error_ixns[0]
        assert "Error" in ix.summary, f"Summary missing 'Error': {ix.summary}"
        # The error class name or code name should appear in summary
        ec_name = ix.details.get("error_class_name", "")
        ecode_name = ix.details.get("error_code_name", "")
        assert ec_name in ix.summary or ecode_name in ix.summary, (
            f"Summary '{ix.summary}' does not contain error class '{ec_name}' "
            f"or error code '{ecode_name}'"
        )


class TestBACnetRejectReason:
    """T1 gap: bacapp.reject_reason."""

    def test_reject_reason_extracted(self):
        """Reject PDUs (type=6) have reject_reason in details."""
        listener, _devices, _result = _run_listener_test(
            "bacnet",
            "BACnetPassiveListener",
            "bacapp",
            "bacnet/cisagov_bacnet_errors.pcap",
            expect_details=["service"],
        )

        reject_ixns = [ix for ix in listener.interactions if ix.details.get("service") == "Reject"]
        assert len(reject_ixns) >= 1, (
            "Expected at least 1 Reject interaction in cisagov_bacnet_errors.pcap"
        )

        has_reason = any("reject_reason" in ix.details for ix in reject_ixns)
        assert has_reason, "No Reject interaction has 'reject_reason' in details"

        # Check human-readable name
        for ix in reject_ixns:
            if "reject_reason" in ix.details:
                assert "reject_reason_name" in ix.details
                assert isinstance(ix.details["reject_reason_name"], str)
                assert ix.details["reject_reason_name"], "reject_reason_name is empty"
                # Summary should include the reason
                assert "Reject" in ix.summary
                break


class TestBACnetAbortReason:
    """T1 gap: bacapp.abort_reason."""

    def test_abort_reason_extracted(self):
        """Abort PDUs (type=7) have abort_reason in details."""
        listener, _devices, _result = _run_listener_test(
            "bacnet",
            "BACnetPassiveListener",
            "bacapp",
            "bacnet/cisagov_bacnet_errors.pcap",
            expect_details=["service"],
        )

        abort_ixns = [ix for ix in listener.interactions if ix.details.get("service") == "Abort"]
        assert len(abort_ixns) >= 1, (
            "Expected at least 1 Abort interaction in cisagov_bacnet_errors.pcap"
        )

        has_reason = any("abort_reason" in ix.details for ix in abort_ixns)
        assert has_reason, "No Abort interaction has 'abort_reason' in details"

        for ix in abort_ixns:
            if "abort_reason" in ix.details:
                assert "abort_reason_name" in ix.details
                assert isinstance(ix.details["abort_reason_name"], str)
                assert ix.details["abort_reason_name"], "abort_reason_name is empty"
                assert "Abort" in ix.summary
                break


class TestBACnetSequenceNumber:
    """T1 gap: bacapp.sequence_number -- segmented transfer tracking."""

    def test_sequence_number_extracted(self):
        """Segmented packets have sequence_number in details."""
        listener, _devices, _result = _run_listener_test(
            "bacnet",
            "BACnetPassiveListener",
            "bacapp",
            "bacnet/cisagov_bacnet_segmented.pcap",
            expect_details=["service"],
        )

        has_seq = any("sequence_number" in ix.details for ix in listener.interactions)
        assert has_seq, (
            "No interaction has 'sequence_number' in details; "
            "segmented pcap should have SegmentAck/ComplexAck with sequence numbers"
        )

        for ix in listener.interactions:
            if "sequence_number" in ix.details:
                assert isinstance(ix.details["sequence_number"], int), (
                    f"sequence_number should be int, got {type(ix.details['sequence_number'])}"
                )
                break


class TestBACnetDeviceIdentifier:
    """T1 gap: bacapp.deviceIdentifier -- BACnet device identity."""

    def test_device_identifier_in_details(self):
        """Packets with deviceIdentifier have it in interaction details."""
        listener, _devices, _result = _run_listener_test(
            "bacnet",
            "BACnetPassiveListener",
            "bacapp",
            "bacnet/cisagov_bacnet_errors.pcap",
            expect_details=["service"],
        )

        has_dev_id = any("device_identifier" in ix.details for ix in listener.interactions)
        assert has_dev_id, (
            "No interaction has 'device_identifier'; "
            "cisagov_bacnet_errors.pcap has packets with bacapp.deviceIdentifier"
        )

        for ix in listener.interactions:
            if "device_identifier" in ix.details:
                assert isinstance(ix.details["device_identifier"], int)
                break

    def test_device_identifier_enriches_device_data(self):
        """device_identifier is stored in device bacnet_passive_data."""
        _listener, devices, _result = _run_listener_test(
            "bacnet",
            "BACnetPassiveListener",
            "bacapp",
            "bacnet/cisagov_bacnet_errors.pcap",
            expect_details=["service"],
        )

        has_enriched = False
        for device in devices.values():
            pd = getattr(device, "bacnet_passive_data", None)
            if pd and "device_identifier" in pd:
                has_enriched = True
                assert isinstance(pd["device_identifier"], int)
                break

        assert has_enriched, (
            "No device has 'device_identifier' in bacnet_passive_data; "
            "device enrichment not working"
        )


class TestBACnetProcessId:
    """T1 gap: bacapp.processId -- subscription process identifier."""

    def test_process_id_extracted(self):
        """Packets with processId have it in interaction details."""
        listener, _devices, _result = _run_listener_test(
            "bacnet",
            "BACnetPassiveListener",
            "bacapp",
            "bacnet/cisagov_bacnet_errors.pcap",
            expect_details=["service"],
        )

        has_proc = any("process_id" in ix.details for ix in listener.interactions)
        assert has_proc, (
            "No interaction has 'process_id'; "
            "cisagov_bacnet_errors.pcap has packets with bacapp.processId"
        )

        for ix in listener.interactions:
            if "process_id" in ix.details:
                assert isinstance(ix.details["process_id"], int)
                break


class TestBACnetHarvestIntegration:
    """Verify harvest() output quality with new fields."""

    def test_harvest_returns_dict(self):
        """harvest() returns a dict (tables are now built centrally by scanner)."""
        _listener, _devices, result = _run_listener_test(
            "bacnet",
            "BACnetPassiveListener",
            "bacapp",
            "bacnet/cisagov_bacnet_errors.pcap",
            expect_details=["service"],
        )

        assert isinstance(result, dict)

    def test_harvest_alerts_for_write_operations(self):
        """harvest() returns write/control alerts when write services detected."""
        _listener, _devices, result = _run_listener_test(
            "bacnet",
            "BACnetPassiveListener",
            "bacapp",
            "bacnet/cisagov_bacnet_errors.pcap",
            expect_details=["service"],
        )

        alerts = result.get("alerts", [])
        write_alerts = [a for a in alerts if "WRITE" in a.get("message", "")]
        # cisagov_bacnet_errors.pcap has WriteProperty and control operations
        assert len(write_alerts) >= 1, (
            f"Expected write alerts, got {len(write_alerts)} alerts total: "
            f"{[a.get('message', '')[:60] for a in alerts]}"
        )

    def test_multiple_pcap_files(self):
        """Listener works across different BACnet pcap fixtures."""
        for pcap_name in (
            "bacnet/cisagov_bacnet_example.pcap",
            "bacnet/cisagov_bacnet_services.pcap",
            "bacnet/ndpi_bacnet.pcap",
        ):
            listener, devices, result = _run_listener_test(
                "bacnet",
                "BACnetPassiveListener",
                "bacapp",
                pcap_name,
                expect_details=["service"],
            )
            assert len(listener.interactions) > 0, f"No interactions from {pcap_name}"
            assert isinstance(result, dict), f"harvest() did not return dict from {pcap_name}"


class _FakeLayer:
    """Minimal pyshark-layer stand-in: only the attrs set are 'present'.

    get_field() uses getattr(layer, name, default), so any attribute we do
    NOT set is treated as an absent tshark field.
    """

    def __init__(self, **fields):
        self.__dict__.update(fields)


class _FakeBACnetPacket:
    """Synthetic BACnet/IP packet with an IP+UDP+bacapp layer."""

    def __init__(self, **bacapp_fields):
        self.ip = _FakeLayer(src="10.0.0.1", dst="10.0.0.2")
        self.udp = _FakeLayer(srcport="47808", dstport="47808", stream="0")
        self.bacapp = _FakeLayer(**bacapp_fields)


class TestBACnetMissingServiceChoice:
    """Regression: APDUs with no service-choice field must not be dropped.

    For ComplexAck/segmented PDUs the confirmed_service choice can be absent
    (it lives on the matching request). Previously process_packet hit
    `if not svc_name: return` and silently dropped the packet with no
    interaction and no debug log. The catch-all now records a generic
    `APDU-<type>` interaction so every bacapp packet yields >= 1 row.
    """

    def test_complexack_without_service_choice_records_interaction(self):
        from oida.pcap.bacnet import BACnetPassiveListener

        listener = BACnetPassiveListener(interface="lo", timeout=10)
        # apdu_type=3 (ComplexAck) but NO confirmed_service field present.
        packet = _FakeBACnetPacket(type="3", invoke_id="7")
        listener.process_packet(packet)

        assert len(listener.interactions) == 1, (
            "ComplexAck with absent service choice was dropped instead of "
            "recording a generic interaction"
        )
        ix = listener.interactions[0]
        assert ix.operation == "APDU-3", f"Expected generic 'APDU-3', got {ix.operation!r}"
        assert ix.details.get("service") == "APDU-3"
        assert ix.direction == "response"
