"""Integration tests for DNS passive listener in EK mode."""

import pytest

from .conftest import _run_listener_test

pytestmark = [pytest.mark.integration]


class TestDNSPassiveEK:
    """DNS-specific tests beyond the parametrized quality suite."""

    # ------------------------------------------------------------------
    # Core query/response parsing
    # ------------------------------------------------------------------

    def test_dns_query_parsing(self):
        listener, devices, result = _run_listener_test(
            "dns",
            "DNSPassiveListener",
            "dns",
            "dns/zeek_dns-binds.pcap",
            expect_details=["query"],
        )
        has_dns_data = any(
            hasattr(d, "dns_passive_data") and d.dns_passive_data for d in devices.values()
        )
        assert has_dns_data, "No device has dns_passive_data"

        queries_found = [
            ix.details.get("query") for ix in listener.interactions if ix.details.get("query")
        ]
        assert len(queries_found) >= 1, "Expected at least one DNS query"

    def test_dns_generated(self):
        listener, devices, result = _run_listener_test(
            "dns",
            "DNSPassiveListener",
            "dns",
            "dns/generated_dns.pcap",
            expect_details=["query"],
        )
        assert len(devices) >= 1

    # ------------------------------------------------------------------
    # Common header fields: opcode, rcode, id, qry_type, authoritative
    # ------------------------------------------------------------------

    def test_common_header_fields_generated(self):
        """Verify opcode, qry_type, id, rcode, authoritative in generated pcap."""
        listener, devices, result = _run_listener_test(
            "dns",
            "DNSPassiveListener",
            "dns",
            "dns/generated_dns.pcap",
            expect_details=["query", "opcode", "qry_type", "id"],
        )
        # At least one response should have rcode and authoritative
        responses = [ix for ix in listener.interactions if ix.direction == "response"]
        assert len(responses) >= 1, "Expected at least one DNS response"

        has_rcode = any(ix.details.get("rcode") is not None for ix in responses)
        assert has_rcode, "No response has rcode field"

        has_auth = any(ix.details.get("authoritative") is not None for ix in responses)
        assert has_auth, "No response has authoritative field"

    def test_opcode_names(self):
        """Verify opcode_name is populated for standard queries."""
        listener, devices, result = _run_listener_test(
            "dns",
            "DNSPassiveListener",
            "dns",
            "dns/generated_dns.pcap",
            expect_details=["opcode"],
        )
        has_opcode_name = any(
            ix.details.get("opcode_name") == "Query" for ix in listener.interactions
        )
        assert has_opcode_name, "Expected opcode_name='Query' for standard queries"

    def test_qry_type_name(self):
        """Verify qry_type_name maps numeric type to string."""
        listener, devices, result = _run_listener_test(
            "dns",
            "DNSPassiveListener",
            "dns",
            "dns/generated_dns.pcap",
            expect_details=["qry_type"],
        )
        type_names = {ix.details.get("qry_type_name") for ix in listener.interactions}
        # generated_dns.pcap has A and AAAA queries
        assert "A" in type_names or "AAAA" in type_names, (
            f"Expected qry_type_name to contain A or AAAA, got {type_names}"
        )

    # ------------------------------------------------------------------
    # Response-specific fields: resp_type, resp_ttl, edns0_version
    # ------------------------------------------------------------------

    def test_resp_ttl_in_details(self):
        """Verify resp_ttl is extracted for response interactions."""
        listener, devices, result = _run_listener_test(
            "dns",
            "DNSPassiveListener",
            "dns",
            "dns/generated_dns.pcap",
            expect_details=["query"],
        )
        responses = [ix for ix in listener.interactions if ix.direction == "response"]
        has_ttl = any(ix.details.get("resp_ttl") is not None for ix in responses)
        assert has_ttl, "No response interaction has resp_ttl field"

    def test_resp_type_in_details(self):
        """Verify resp_type is extracted for response interactions."""
        listener, devices, result = _run_listener_test(
            "dns",
            "DNSPassiveListener",
            "dns",
            "dns/generated_dns.pcap",
            expect_details=["query"],
        )
        responses = [ix for ix in listener.interactions if ix.direction == "response"]
        has_type = any(ix.details.get("resp_type") is not None for ix in responses)
        assert has_type, "No response interaction has resp_type field"

    def test_edns0_version_in_details(self):
        """Verify edns0_version is extracted when EDNS0 is present."""
        listener, devices, result = _run_listener_test(
            "dns",
            "DNSPassiveListener",
            "dns",
            "dns/zeek_dns-binds.pcap",
            expect_details=["query"],
        )
        responses = [ix for ix in listener.interactions if ix.direction == "response"]
        has_edns0 = any(ix.details.get("edns0_version") is not None for ix in responses)
        assert has_edns0, "No response has edns0_version (binds pcap has EDNS0)"

    # ------------------------------------------------------------------
    # check_disabled (CD) flag -- DNSSEC
    # ------------------------------------------------------------------

    def test_check_disabled_flag(self):
        """Verify check_disabled flag is extracted."""
        listener, devices, result = _run_listener_test(
            "dns",
            "DNSPassiveListener",
            "dns",
            "dns/generated_dns.pcap",
            expect_details=["query"],
        )
        has_cd = any(ix.details.get("check_disabled") is not None for ix in listener.interactions)
        assert has_cd, "No interaction has check_disabled field"

    # ------------------------------------------------------------------
    # MX records
    # ------------------------------------------------------------------

    def test_mx_records(self):
        """Verify MX records are parsed from long-connection pcap."""
        listener, devices, result = _run_listener_test(
            "dns",
            "DNSPassiveListener",
            "dns",
            "dns/zeek_long-connection.pcap",
            expect_details=["query"],
        )
        all_responses = []
        for dev in devices.values():
            if hasattr(dev, "dns_passive_data") and dev.dns_passive_data:
                all_responses.extend(dev.dns_passive_data.get("responses", []))

        mx_records = [r for r in all_responses if r.get("type") == "MX"]
        assert len(mx_records) >= 1, (
            f"Expected MX records in zeek_long-connection.pcap; "
            f"types seen: {sorted(set(r.get('type') for r in all_responses))}"
        )
        assert any("google.com" in str(r.get("answer", "")) for r in mx_records), (
            "Expected google.com MX records"
        )

    # ------------------------------------------------------------------
    # SOA records
    # ------------------------------------------------------------------

    def test_soa_records(self):
        """Verify SOA records are parsed from sshfp-trunc pcap."""
        listener, devices, result = _run_listener_test(
            "dns",
            "DNSPassiveListener",
            "dns",
            "dns/zeek_sshfp-trunc.pcap",
            expect_details=["query"],
        )
        all_responses = []
        for dev in devices.values():
            if hasattr(dev, "dns_passive_data") and dev.dns_passive_data:
                all_responses.extend(dev.dns_passive_data.get("responses", []))

        soa_records = [r for r in all_responses if r.get("type") == "SOA"]
        assert len(soa_records) >= 1, "Expected SOA records in zeek_sshfp-trunc.pcap"
        assert any(r.get("mname") for r in soa_records), "SOA record should have mname"
        assert any(r.get("rname") for r in soa_records), "SOA record should have rname"

    # ------------------------------------------------------------------
    # RRSIG records (DNSSEC)
    # ------------------------------------------------------------------

    def test_rrsig_records(self):
        """Verify RRSIG records are parsed from sshfp-trunc pcap."""
        listener, devices, result = _run_listener_test(
            "dns",
            "DNSPassiveListener",
            "dns",
            "dns/zeek_sshfp-trunc.pcap",
            expect_details=["query"],
        )
        all_responses = []
        for dev in devices.values():
            if hasattr(dev, "dns_passive_data") and dev.dns_passive_data:
                all_responses.extend(dev.dns_passive_data.get("responses", []))

        rrsig_records = [r for r in all_responses if r.get("type") == "RRSIG"]
        assert len(rrsig_records) >= 1, "Expected RRSIG records in zeek_sshfp-trunc.pcap"
        assert any("lbl.gov" in str(r.get("answer", "")) for r in rrsig_records), (
            "RRSIG should have signers_name containing lbl.gov"
        )

    # ------------------------------------------------------------------
    # NSEC records (DNSSEC)
    # ------------------------------------------------------------------

    def test_nsec_records(self):
        """Verify NSEC records are parsed from sshfp-trunc pcap."""
        listener, devices, result = _run_listener_test(
            "dns",
            "DNSPassiveListener",
            "dns",
            "dns/zeek_sshfp-trunc.pcap",
            expect_details=["query"],
        )
        all_responses = []
        for dev in devices.values():
            if hasattr(dev, "dns_passive_data") and dev.dns_passive_data:
                all_responses.extend(dev.dns_passive_data.get("responses", []))

        nsec_records = [r for r in all_responses if r.get("type") == "NSEC"]
        assert len(nsec_records) >= 1, "Expected NSEC records in zeek_sshfp-trunc.pcap"

    # ------------------------------------------------------------------
    # TSIG records
    # ------------------------------------------------------------------

    def test_tsig_records(self):
        """Verify TSIG records are parsed from dynamic-update pcap."""
        listener, devices, result = _run_listener_test(
            "dns",
            "DNSPassiveListener",
            "dns",
            "dns/zeek_dynamic-update.pcap",
            expect_details=["query"],
        )
        all_responses = []
        for dev in devices.values():
            if hasattr(dev, "dns_passive_data") and dev.dns_passive_data:
                all_responses.extend(dev.dns_passive_data.get("responses", []))

        tsig_records = [r for r in all_responses if r.get("type") == "TSIG"]
        assert len(tsig_records) >= 1, "Expected TSIG records in zeek_dynamic-update.pcap"
        assert any("gss-tsig" in str(r.get("algorithm", "")) for r in tsig_records), (
            "TSIG record should have gss-tsig algorithm"
        )

    # ------------------------------------------------------------------
    # TKEY records
    # ------------------------------------------------------------------

    def test_tkey_records(self):
        """Verify TKEY records are parsed from tkey pcap."""
        listener, devices, result = _run_listener_test(
            "dns",
            "DNSPassiveListener",
            "dns",
            "dns/zeek_tkey.pcap",
            expect_details=["query"],
        )
        all_responses = []
        for dev in devices.values():
            if hasattr(dev, "dns_passive_data") and dev.dns_passive_data:
                all_responses.extend(dev.dns_passive_data.get("responses", []))

        tkey_records = [r for r in all_responses if r.get("type") == "TKEY"]
        assert len(tkey_records) >= 1, "Expected TKEY records in zeek_tkey.pcap"
        assert any("gss-tsig" in str(r.get("algorithm", "")) for r in tkey_records), (
            "TKEY record should have gss-tsig algorithm"
        )

    # ------------------------------------------------------------------
    # LOC records
    # ------------------------------------------------------------------

    def test_loc_records(self):
        """Verify LOC records are parsed from loc-29-trunc pcap."""
        listener, devices, result = _run_listener_test(
            "dns",
            "DNSPassiveListener",
            "dns",
            "dns/zeek_loc-29-trunc.pcap",
            expect_details=["query"],
        )
        all_responses = []
        for dev in devices.values():
            if hasattr(dev, "dns_passive_data") and dev.dns_passive_data:
                all_responses.extend(dev.dns_passive_data.get("responses", []))

        loc_records = [r for r in all_responses if r.get("type") == "LOC"]
        assert len(loc_records) >= 1, "Expected LOC records in zeek_loc-29-trunc.pcap"
        assert any(r.get("version") == "0" for r in loc_records), "LOC record should have version=0"

    # ------------------------------------------------------------------
    # NAPTR records
    # ------------------------------------------------------------------

    def test_naptr_records(self):
        """Verify NAPTR records are parsed from naptr pcap."""
        listener, devices, result = _run_listener_test(
            "dns",
            "DNSPassiveListener",
            "dns",
            "dns/zeek_naptr.pcap",
            expect_details=["query"],
        )
        all_responses = []
        for dev in devices.values():
            if hasattr(dev, "dns_passive_data") and dev.dns_passive_data:
                all_responses.extend(dev.dns_passive_data.get("responses", []))

        naptr_records = [r for r in all_responses if r.get("type") == "NAPTR"]
        assert len(naptr_records) >= 1, "Expected NAPTR records in zeek_naptr.pcap"
        assert any(r.get("service") for r in naptr_records), (
            "NAPTR record should have service field"
        )

    # ------------------------------------------------------------------
    # Dynamic Update (opcode=5)
    # ------------------------------------------------------------------

    def test_dynamic_update_opcode(self):
        """Verify opcode=5 (Update) is parsed from dynamic-update pcap."""
        listener, devices, result = _run_listener_test(
            "dns",
            "DNSPassiveListener",
            "dns",
            "dns/zeek_dynamic-update.pcap",
            expect_details=["query", "opcode"],
        )
        has_update = any(
            ix.details.get("opcode") == "5" or ix.details.get("opcode_name") == "Update"
            for ix in listener.interactions
        )
        assert has_update, "Expected opcode=5 (Update) in dynamic-update pcap"

    # ------------------------------------------------------------------
    # NXDOMAIN (rcode=3) detection
    # ------------------------------------------------------------------

    def test_nxdomain_rcode(self):
        """Verify rcode=3 (NXDOMAIN) is detected in long-connection pcap."""
        listener, devices, result = _run_listener_test(
            "dns",
            "DNSPassiveListener",
            "dns",
            "dns/zeek_long-connection.pcap",
            expect_details=["query"],
        )
        responses = [ix for ix in listener.interactions if ix.direction == "response"]
        has_nxdomain = any(
            ix.details.get("rcode") == "3"
            or ix.details.get("rcode_name") == "Name Error (NXDOMAIN)"
            for ix in responses
        )
        assert has_nxdomain, "Expected rcode=3 (NXDOMAIN) in zeek_long-connection.pcap"

    # ------------------------------------------------------------------
    # TTL in response records
    # ------------------------------------------------------------------

    def test_ttl_in_response_records(self):
        """Verify TTL is stored in individual response record dicts."""
        listener, devices, result = _run_listener_test(
            "dns",
            "DNSPassiveListener",
            "dns",
            "dns/generated_dns.pcap",
            expect_details=["query"],
        )
        all_responses = []
        for dev in devices.values():
            if hasattr(dev, "dns_passive_data") and dev.dns_passive_data:
                all_responses.extend(dev.dns_passive_data.get("responses", []))

        has_ttl = any(r.get("ttl") is not None for r in all_responses)
        assert has_ttl, "Expected ttl field in response records"

    # ------------------------------------------------------------------
    # T1 gap fixes: count_auth_rr, tsig.original_id, soa.rname.name
    # ------------------------------------------------------------------

    def test_count_auth_rr_in_details(self):
        """Verify count_auth_rr header field is extracted (T1 gap)."""
        listener, devices, result = _run_listener_test(
            "dns",
            "DNSPassiveListener",
            "dns",
            "dns/zeek_sshfp-trunc.pcap",
            expect_details=["query"],
        )
        # sshfp-trunc has responses with 6 authoritative records
        has_auth_count = any(
            ix.details.get("count_auth_rr") not in (None, "0") for ix in listener.interactions
        )
        assert has_auth_count, (
            "Expected non-zero count_auth_rr in zeek_sshfp-trunc.pcap; "
            f"sample details: {listener.interactions[0].details if listener.interactions else 'none'}"
        )

    def test_tsig_original_id(self):
        """Verify TSIG original_id is extracted (T1 gap)."""
        listener, devices, result = _run_listener_test(
            "dns",
            "DNSPassiveListener",
            "dns",
            "dns/zeek_tkey.pcap",
            expect_details=["query"],
        )
        all_responses = []
        for dev in devices.values():
            if hasattr(dev, "dns_passive_data") and dev.dns_passive_data:
                all_responses.extend(dev.dns_passive_data.get("responses", []))

        tsig_records = [r for r in all_responses if r.get("type") == "TSIG"]
        assert len(tsig_records) >= 1, "Expected TSIG records in zeek_tkey.pcap"
        assert any(r.get("original_id") for r in tsig_records), (
            "TSIG record should have original_id field"
        )

    def test_soa_rname_email(self):
        """Verify SOA rname email-form is extracted (T1 gap)."""
        listener, devices, result = _run_listener_test(
            "dns",
            "DNSPassiveListener",
            "dns",
            "dns/zeek_sshfp-trunc.pcap",
            expect_details=["query"],
        )
        all_responses = []
        for dev in devices.values():
            if hasattr(dev, "dns_passive_data") and dev.dns_passive_data:
                all_responses.extend(dev.dns_passive_data.get("responses", []))

        soa_records = [r for r in all_responses if r.get("type") == "SOA"]
        assert len(soa_records) >= 1, "Expected SOA records in zeek_sshfp-trunc.pcap"
        assert any("@" in str(r.get("rname_email", "")) for r in soa_records), (
            "SOA record should have email-form rname_email (with @)"
        )
