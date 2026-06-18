"""Integration tests for MMS passive listener in EK mode."""

import pytest

from .conftest import _run_listener_test

pytestmark = [pytest.mark.integration]


class TestMMSPassiveEK:
    """MMS-specific tests beyond the parametrized quality suite."""

    def test_mms_service_operations(self):
        listener, devices, result = _run_listener_test(
            "mms",
            "MMSPassiveListener",
            "acse or mms",
            "mms/iti_iec61850_session.pcap",
        )

        # A1: passive_data on at least one device
        has_data = any(
            hasattr(d, "mms_passive_data") and d.mms_passive_data for d in devices.values()
        )
        assert has_data, "No device has mms_passive_data"

        # A2: harvest returns a dict (tables are now built centrally by scanner)
        assert isinstance(result, dict)

        # A3: MMS operations include ACSE or MMS service names
        seen_ops = {ix.operation for ix in listener.interactions if ix.operation}
        assert seen_ops, "No operations recorded"


class TestMMSInvokeID:
    """mms.invokeID — request/response correlation identifier."""

    def test_invoke_id_present_on_confirmed_services(self):
        """invokeID should appear on all confirmed request/response interactions."""
        listener, _, _ = _run_listener_test(
            "mms",
            "MMSPassiveListener",
            "acse or mms",
            "mms/iti_iec61850_session.pcap",
        )

        confirmed = [
            ix for ix in listener.interactions if ix.details.get("service_code") is not None
        ]
        assert confirmed, "No confirmed service interactions found"

        with_invoke = [ix for ix in confirmed if ix.details.get("invoke_id") is not None]
        assert len(with_invoke) == len(confirmed), (
            f"Only {len(with_invoke)}/{len(confirmed)} confirmed services "
            f"have invoke_id. Missing: "
            f"{[ix.summary[:40] for ix in confirmed if 'invoke_id' not in ix.details][:3]}"
        )

    def test_invoke_id_is_numeric_string(self):
        """invokeID values should be numeric strings (int serialized)."""
        listener, _, _ = _run_listener_test(
            "mms",
            "MMSPassiveListener",
            "acse or mms",
            "mms/iti_iec61850_session.pcap",
        )

        for ix in listener.interactions:
            inv = ix.details.get("invoke_id")
            if inv is not None:
                assert str(inv).lstrip("-").isdigit(), (
                    f"invoke_id {inv!r} is not numeric in {ix.summary[:40]}"
                )
                break
        else:
            pytest.skip("No invoke_id found")


class TestMMSErrorFields:
    """mms.errorClass and mms.failure — error classification fields."""

    def test_error_class_extraction(self):
        """errorClass should be extracted from confirmed_ErrorPDU packets."""
        listener, _, _ = _run_listener_test(
            "mms",
            "MMSPassiveListener",
            "acse or mms",
            "mms/iti_mms_and_goose.pcap",
        )

        errors = [ix for ix in listener.interactions if ix.details.get("error_class") is not None]
        assert errors, "No error interactions found in mms_and_goose.pcap"

        err = errors[0]
        assert err.operation == "Error", f"Expected 'Error' operation, got {err.operation!r}"
        assert err.details.get("error_class_name"), "Missing error_class_name"
        # error_class 7 = "access"
        assert err.details["error_class"] == 7, (
            f"Expected error_class 7, got {err.details['error_class']}"
        )
        assert err.details["error_class_name"] == "access"

    def test_error_has_invoke_id(self):
        """Error PDUs should carry invoke_id for correlation."""
        listener, _, _ = _run_listener_test(
            "mms",
            "MMSPassiveListener",
            "acse or mms",
            "mms/iti_mms_and_goose.pcap",
        )

        errors = [ix for ix in listener.interactions if ix.details.get("error_class") is not None]
        assert errors, "No error interactions found"
        assert errors[0].details.get("invoke_id"), "Error missing invoke_id"

    def test_failure_extraction(self):
        """mms.failure (DataAccessError) should be extracted from read responses."""
        listener, _, _ = _run_listener_test(
            "mms",
            "MMSPassiveListener",
            "acse or mms",
            "mms/iti_mms_and_goose.pcap",
        )

        failures = [ix for ix in listener.interactions if ix.details.get("failure") is not None]
        assert failures, "No failure interactions found in mms_and_goose.pcap"
        # failure code 10 = object-access-unsupported
        assert failures[0].details["failure"] == "10"


class TestMMSUnconfirmedService:
    """mms.unconfirmedService — unconfirmed service type classification."""

    def test_unconfirmed_service_on_information_report(self):
        """InformationReport interactions should include unconfirmed_service code."""
        listener, _, _ = _run_listener_test(
            "mms",
            "MMSPassiveListener",
            "acse or mms",
            "mms/iti_iec61850_session.pcap",
        )

        reports = [ix for ix in listener.interactions if ix.operation == "informationReport"]
        assert reports, "No informationReport interactions found"

        with_unconf = [ix for ix in reports if ix.details.get("unconfirmed_service") is not None]
        assert with_unconf, (
            "No informationReport has unconfirmed_service field. "
            f"Sample details: {reports[0].details}"
        )
        # informationReport = 0
        assert with_unconf[0].details["unconfirmed_service"] == 0


class TestACSEResultFields:
    """acse.result and acse.result_source_diagnostic — AARE fields."""

    def test_acse_result_on_aare(self):
        """AARE interactions should carry association result code."""
        listener, _, _ = _run_listener_test(
            "mms",
            "MMSPassiveListener",
            "acse or mms",
            "mms/iti_iec61850_session.pcap",
        )

        aare_ixs = [
            ix
            for ix in listener.interactions
            if ix.operation == "ACSE Associate" and ix.direction == "response"
        ]
        assert aare_ixs, "No ACSE AARE interactions found"

        aare = aare_ixs[0]
        assert "result" in aare.details, f"AARE missing 'result'; details: {aare.details}"
        assert aare.details["result"] == 0, (
            f"Expected result=0 (accepted), got {aare.details['result']}"
        )
        assert aare.details.get("result_name") == "accepted"

    def test_acse_result_source_diagnostic(self):
        """AARE interactions should carry result_source_diagnostic."""
        listener, _, _ = _run_listener_test(
            "mms",
            "MMSPassiveListener",
            "acse or mms",
            "mms/iti_iec61850_session.pcap",
        )

        aare_ixs = [
            ix
            for ix in listener.interactions
            if ix.operation == "ACSE Associate" and ix.direction == "response"
        ]
        assert aare_ixs, "No ACSE AARE interactions found"
        assert "result_source_diagnostic" in aare_ixs[0].details, (
            f"AARE missing result_source_diagnostic; details: {aare_ixs[0].details}"
        )

    def test_acse_aarq_recorded(self):
        """AARQ (Associate Request) should be recorded as interaction."""
        listener, _, _ = _run_listener_test(
            "mms",
            "MMSPassiveListener",
            "acse or mms",
            "mms/iti_iec61850_session.pcap",
        )

        aarq_ixs = [
            ix
            for ix in listener.interactions
            if ix.operation == "ACSE Associate" and ix.direction == "request"
        ]
        assert aarq_ixs, "No ACSE AARQ interactions found"


class TestMMSDomainSpecific:
    """mms.domainSpecific — domain-specific scope identifier."""

    def test_domain_specific_in_get_name_list(self):
        """getNameList requests should include domainSpecific scope."""
        listener, _, _ = _run_listener_test(
            "mms",
            "MMSPassiveListener",
            "acse or mms",
            "mms/iti_iec61850_session.pcap",
        )

        getnl = [
            ix
            for ix in listener.interactions
            if ix.details.get("service_name") == "getNameList" and ix.direction == "request"
        ]
        assert getnl, "No getNameList requests found"

        with_domain_specific = [ix for ix in getnl if ix.details.get("domain_specific")]
        assert with_domain_specific, (
            f"No getNameList request has domain_specific. Sample details: {getnl[0].details}"
        )
        # Known domain names in the fixture
        ds = with_domain_specific[0].details["domain_specific"]
        assert ds in ("KIRKLAND", "BELLEVUE"), f"Unexpected domain_specific: {ds}"


class TestMMSIdentifiers:
    """mms.Identifier — identifier list in getNameList responses."""

    def test_identifiers_in_get_name_list_response(self):
        """getNameList responses should include extracted identifier list."""
        listener, _, _ = _run_listener_test(
            "mms",
            "MMSPassiveListener",
            "acse or mms",
            "mms/iti_iec61850_session.pcap",
        )

        getnl_resp = [
            ix
            for ix in listener.interactions
            if ix.details.get("service_name") == "getNameList" and ix.direction == "response"
        ]
        assert getnl_resp, "No getNameList responses found"

        with_ids = [ix for ix in getnl_resp if ix.details.get("identifiers")]
        assert with_ids, (
            f"No getNameList response has identifiers. Sample details: {getnl_resp[0].details}"
        )

        ids = with_ids[0].details["identifiers"]
        assert isinstance(ids, list), f"identifiers should be a list, got {type(ids)}"
        assert len(ids) >= 1, "Expected at least 1 identifier"
        # Known identifiers from fixture
        assert "EMS_ANALOG_ICCP_IN" in ids or "ANALOG_ICCP_IN" in ids, (
            f"Expected known identifiers, got {ids}"
        )


class TestMMSServicesSupportedCalling:
    """mms.servicesSupportedCalling — client capability bitmask."""

    def test_services_supported_calling_in_initiate_request(self):
        """Initiate Request should include servicesSupportedCalling bitmask."""
        listener, _, _ = _run_listener_test(
            "mms",
            "MMSPassiveListener",
            "acse or mms",
            "mms/iti_iec61850_session.pcap",
        )

        init_req = [
            ix
            for ix in listener.interactions
            if ix.operation == "Initiate" and ix.direction == "request"
        ]
        assert init_req, "No Initiate Request interactions found"

        assert init_req[0].details.get("services_supported_calling"), (
            f"Initiate Request missing services_supported_calling; details: {init_req[0].details}"
        )

    def test_services_supported_calling_enriches_device(self):
        """Client device should have services_supported in passive_data."""
        listener, devices, _ = _run_listener_test(
            "mms",
            "MMSPassiveListener",
            "acse or mms",
            "mms/iti_iec61850_session.pcap",
        )

        client_devices = [
            d
            for d in devices.values()
            if hasattr(d, "mms_passive_data")
            and d.mms_passive_data
            and d.mms_passive_data.get("role") == "client"
        ]
        assert client_devices, "No client device found"

        pd = client_devices[0].mms_passive_data
        assert "services_bitmask" in pd, (
            f"Client device missing services_bitmask; keys: {list(pd.keys())}"
        )
        assert "services_supported" in pd, (
            f"Client device missing services_supported; keys: {list(pd.keys())}"
        )
        assert isinstance(pd["services_supported"], list)
        assert len(pd["services_supported"]) >= 1


class TestMMSServicesSupportedCalled:
    """mms.servicesSupportedCalled — server capability bitmask."""

    def test_services_supported_called_in_initiate_response(self):
        """Initiate Response should include servicesSupportedCalled bitmask."""
        listener, _, _ = _run_listener_test(
            "mms",
            "MMSPassiveListener",
            "acse or mms",
            "mms/iti_iec61850_session.pcap",
        )

        init_resp = [
            ix
            for ix in listener.interactions
            if ix.operation == "Initiate" and ix.direction == "response"
        ]
        assert init_resp, "No Initiate Response interactions found"

        assert init_resp[0].details.get("services_supported_called"), (
            f"Initiate Response missing services_supported_called; details: {init_resp[0].details}"
        )

    def test_services_supported_called_enriches_device(self):
        """Server device should have services_supported in passive_data."""
        listener, devices, _ = _run_listener_test(
            "mms",
            "MMSPassiveListener",
            "acse or mms",
            "mms/iti_iec61850_session.pcap",
        )

        server_devices = [
            d
            for d in devices.values()
            if hasattr(d, "mms_passive_data")
            and d.mms_passive_data
            and d.mms_passive_data.get("role") == "server"
        ]
        assert server_devices, "No server device found"

        pd = server_devices[0].mms_passive_data
        assert "services_bitmask" in pd, (
            f"Server device missing services_bitmask; keys: {list(pd.keys())}"
        )
        assert "services_supported" in pd, (
            f"Server device missing services_supported; keys: {list(pd.keys())}"
        )
        svcs = pd["services_supported"]
        assert isinstance(svcs, list)
        assert "read" in svcs, f"Expected 'read' in services_supported, got {svcs}"
        assert "write" in svcs, f"Expected 'write' in services_supported, got {svcs}"


class TestMMSGetVariableAccessAttributes:
    """mms.getVariableAccessAttributes — request type selector."""

    def test_get_var_access_attr_extraction(self):
        """getVariableAccessAttributes request should include type selector."""
        listener, _, _ = _run_listener_test(
            "mms",
            "MMSPassiveListener",
            "acse or mms",
            "mms/iti_iec61850_get_variable_access_attributes.pcap",
            min_devices=0,
        )

        gva = [
            ix
            for ix in listener.interactions
            if ix.details.get("service_name") == "getVariableAccessAttributes"
            and ix.direction == "request"
        ]
        assert gva, "No getVariableAccessAttributes requests found"

        assert gva[0].details.get("get_var_access_attr") is not None, (
            f"getVariableAccessAttributes missing get_var_access_attr; details: {gva[0].details}"
        )


class TestMMSGetNamedVariableListAttributes:
    """mms.getNamedVariableListAttributes — request ObjectName selector."""

    def test_get_named_var_list_attr_extraction(self):
        """getNamedVariableListAttributes request should include selector."""
        listener, _, _ = _run_listener_test(
            "mms",
            "MMSPassiveListener",
            "acse or mms",
            "mms/iti_iec61850_session.pcap",
        )

        gnvla = [
            ix
            for ix in listener.interactions
            if ix.details.get("service_name") == "getNamedVariableListAttributes"
            and ix.direction == "request"
        ]
        assert gnvla, "No getNamedVariableListAttributes requests found"

        assert gnvla[0].details.get("get_named_var_list_attr") is not None, (
            f"getNamedVariableListAttributes missing get_named_var_list_attr; "
            f"details: {gnvla[0].details}"
        )


class TestMMSExtendedObjectClass:
    """mms.extendedObjectClass — extended object class in getNameList."""

    def test_extended_object_class_in_get_name_list(self):
        """getNameList requests should include extendedObjectClass."""
        listener, _, _ = _run_listener_test(
            "mms",
            "MMSPassiveListener",
            "acse or mms",
            "mms/iti_iec61850_session.pcap",
        )

        getnl = [
            ix
            for ix in listener.interactions
            if ix.details.get("service_name") == "getNameList" and ix.direction == "request"
        ]
        assert getnl, "No getNameList requests found"

        with_ext = [ix for ix in getnl if ix.details.get("extended_object_class") is not None]
        assert with_ext, (
            f"No getNameList request has extended_object_class. Sample details: {getnl[0].details}"
        )
