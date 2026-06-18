"""Integration tests for Kerberos passive listener in EK mode.

Tests cover all T1 tshark field extractions:
- kerberos.error_code: KRB-ERROR error code detection
- kerberos.cname_string: CNameString sequence count
- kerberos.sname_string: SNameString sequence count
- kerberos.name_string: generic KerberosString sequence count
- kerberos.encryptedAuthenticator_cipher: AP-REQ authenticator cipher
- kerberos.rEQ_SEQUENCE_OF_PA_DATA: PA-DATA count in requests
- kerberos.rEP_SEQUENCE_OF_PA_DATA: PA-DATA count in replies
- kerberos.kdc-req-body.etype: requested etype count
- kerberos.checksum: authenticator checksum
- kerberos.addr_nb: NetBIOS client hostname
- kerberos.addresses: host address count
"""

import pytest

from .conftest import _run_listener_test

pytestmark = [pytest.mark.integration]


class TestKerberosPassiveEK:
    """Kerberos-specific tests beyond the parametrized quality suite."""

    def test_kerberos_hashes_extracted(self):
        listener, devices, result = _run_listener_test(
            "kerberos",
            "KerberosPassiveListener",
            "kerberos",
            "kerberos/bruteshark_kerberos_v5_tcp.pcap",
            expect_details=["msg_type"],
        )

        # Kerberos hash extraction
        hashes = listener.get_hashes_summary()
        assert len(hashes) >= 1, f"Expected at least 1 hash, got {len(hashes)}"
        for h in hashes:
            assert h["protocol"] == "Kerberos"
            assert h["username"], "Hash missing username"
            assert h["domain"], "Hash missing domain"

        # Hashcat export
        hashcat_lines = listener.get_hashcat_hashes()
        assert len(hashcat_lines) >= 1, "No hashcat-format hashes produced"


class TestKerberosErrorCodeExtraction:
    """T1 field: kerberos.error_code -- KRB-ERROR detection."""

    def test_error_code_in_interaction_details(self):
        """KRB-ERROR packets must have error_code in interaction details."""
        listener, devices, result = _run_listener_test(
            "kerberos",
            "KerberosPassiveListener",
            "kerberos",
            "kerberos/bruteshark_kerberos_v5_tcp.pcap",
            expect_details=["msg_type"],
        )

        # bruteshark_kerberos_v5_tcp has KRB-ERROR with code 25 (PREAUTH_REQUIRED)
        error_interactions = [ix for ix in listener.interactions if ix.details.get("error_code")]
        assert len(error_interactions) >= 1, (
            "No interactions with error_code found; "
            f"saw details keys: {[list(ix.details.keys()) for ix in listener.interactions[:3]]}"
        )

        # Verify error_code and error_name are populated
        for ix in error_interactions:
            assert isinstance(ix.details["error_code"], int)
            assert ix.details["error_name"], "error_name should be set"

    def test_error_code_25_preauth_required(self):
        """Error code 25 (PREAUTH_REQUIRED) is extracted and named."""
        listener, devices, result = _run_listener_test(
            "kerberos",
            "KerberosPassiveListener",
            "kerberos",
            "kerberos/bruteshark_kerberos_v5_tcp.pcap",
            expect_details=["msg_type"],
        )

        preauth_errors = [ix for ix in listener.interactions if ix.details.get("error_code") == 25]
        assert len(preauth_errors) >= 1, "Expected at least one PREAUTH_REQUIRED error"
        assert preauth_errors[0].details["error_name"] == "KDC_ERR_PREAUTH_REQUIRED"

    def test_error_code_tracking_in_counts(self):
        """Error codes are tracked in listener.error_counts."""
        listener, devices, result = _run_listener_test(
            "kerberos",
            "KerberosPassiveListener",
            "kerberos",
            "kerberos/bruteshark_kerberos_v5_tcp.pcap",
            expect_details=["msg_type"],
        )

        assert len(listener.error_counts) >= 1, "error_counts should be populated"
        # Each key is (kdc_ip, error_code, username, realm)
        for key, count in listener.error_counts.items():
            assert len(key) == 4
            assert isinstance(key[1], int), "error_code in key should be int"
            assert count >= 1

    def test_error_code_14_etype_nosupp(self):
        """Error code 14 (ETYPE_NOSUPP) in wireshark_krb816.cap."""
        listener, devices, result = _run_listener_test(
            "kerberos",
            "KerberosPassiveListener",
            "kerberos",
            "kerberos/wireshark_krb816.cap",
            expect_details=["msg_type"],
        )

        etype_errors = [ix for ix in listener.interactions if ix.details.get("error_code") == 14]
        assert len(etype_errors) >= 1, "Expected ETYPE_NOSUPP error from wireshark_krb816.cap"
        assert etype_errors[0].details["error_name"] == "KDC_ERR_ETYPE_NOSUPP"

    def test_error_code_60_generic(self):
        """Error code 60 (KRB_ERR_GENERIC) in bruteshark_kerberos_udp.pcap."""
        # This pcap is a loopback capture (127.0.0.x / 0.0.0.0) so no devices
        listener, devices, result = _run_listener_test(
            "kerberos",
            "KerberosPassiveListener",
            "kerberos",
            "kerberos/bruteshark_kerberos_udp.pcap",
            min_devices=0,
            expect_details=["msg_type"],
        )

        generic_errors = [ix for ix in listener.interactions if ix.details.get("error_code") == 60]
        assert len(generic_errors) >= 1, "Expected KRB_ERR_GENERIC error"
        assert generic_errors[0].details["error_name"] == "KRB_ERR_GENERIC"


class TestKerberosErrorDeviceEnrichment:
    """KRB-ERROR should enrich device entries with error tracking."""

    def test_kdc_device_has_error_codes_seen(self):
        """KDC device passive data should include error_codes_seen."""
        listener, devices, result = _run_listener_test(
            "kerberos",
            "KerberosPassiveListener",
            "kerberos",
            "kerberos/bruteshark_kerberos_v5_tcp.pcap",
            expect_details=["msg_type"],
        )

        kdc_devices = [
            d
            for d in devices.values()
            if hasattr(d, "kerberos_passive_data")
            and d.kerberos_passive_data
            and d.kerberos_passive_data.get("role") == "kdc"
        ]
        assert len(kdc_devices) >= 1, "Expected at least one KDC device"
        # KDC should have error_codes_seen from KRB-ERROR messages
        kdc = kdc_devices[0]
        error_codes = kdc.kerberos_passive_data.get("error_codes_seen", [])
        assert 25 in error_codes, f"Expected error code 25 in KDC; got {error_codes}"


class TestKerberosHarvestErrorAlerts:
    """harvest() should produce alerts for security-relevant errors."""

    def test_harvest_skips_preauth_required_alerts(self):
        """PREAUTH_REQUIRED (25) is normal -- no alert generated."""
        listener, devices, result = _run_listener_test(
            "kerberos",
            "KerberosPassiveListener",
            "kerberos",
            "kerberos/bruteshark_kerberos_v5_tcp.pcap",
            expect_details=["msg_type"],
        )

        alerts = result.get("alerts", [])
        # Error code 25 is normal negotiation, should not generate alerts
        preauth_alerts = [a for a in alerts if "PREAUTH_REQUIRED" in a.get("message", "")]
        assert len(preauth_alerts) == 0, (
            f"PREAUTH_REQUIRED should not produce alerts; got {preauth_alerts}"
        )

    def test_harvest_alerts_for_error_60(self):
        """KRB_ERR_GENERIC (60) should produce a warning alert."""
        # Loopback capture -- no devices expected
        listener, devices, result = _run_listener_test(
            "kerberos",
            "KerberosPassiveListener",
            "kerberos",
            "kerberos/bruteshark_kerberos_udp.pcap",
            min_devices=0,
            expect_details=["msg_type"],
        )

        alerts = result.get("alerts", [])
        generic_alerts = [a for a in alerts if "KRB_ERR_GENERIC" in a.get("message", "")]
        assert len(generic_alerts) >= 1, f"Expected KRB_ERR_GENERIC alert; got alerts: {alerts}"
        assert generic_alerts[0]["level"] == "warning"
        assert generic_alerts[0]["category"] == "auth_error"


class TestKerberosCNameStringCount:
    """T1 field: kerberos.cname_string -- CNameString sequence count."""

    def test_cname_string_count_in_details(self):
        """AS-REQ packets should have cname_string_count in details."""
        listener, devices, result = _run_listener_test(
            "kerberos",
            "KerberosPassiveListener",
            "kerberos",
            "kerberos/bruteshark_kerberos_v5_tcp.pcap",
            expect_details=["msg_type"],
        )

        # AS-REQ (msg_type=10) should have cname_string_count
        as_req = [ix for ix in listener.interactions if ix.details.get("msg_type") == 10]
        assert len(as_req) >= 1, "Expected at least one AS-REQ interaction"

        with_count = [ix for ix in as_req if ix.details.get("cname_string_count")]
        assert len(with_count) >= 1, (
            f"Expected cname_string_count in AS-REQ details; keys: {list(as_req[0].details.keys())}"
        )


class TestKerberosSNameStringCount:
    """T1 field: kerberos.sname_string -- SNameString sequence count."""

    def test_sname_string_count_in_details(self):
        """Interactions should have sname_string_count in details."""
        listener, devices, result = _run_listener_test(
            "kerberos",
            "KerberosPassiveListener",
            "kerberos",
            "kerberos/bruteshark_kerberos_v5_tcp.pcap",
            expect_details=["msg_type"],
        )

        with_count = [ix for ix in listener.interactions if ix.details.get("sname_string_count")]
        assert len(with_count) >= 1, "Expected at least one interaction with sname_string_count"


class TestKerberosNameStringCount:
    """T1 field: kerberos.name_string -- generic KerberosString count."""

    def test_name_string_count_in_details(self):
        """AS-REP with KerberosString should have name_string_count."""
        # This field appears in bruteshark_kerberos_v5_tcp.pcap (in AS-REP)
        listener, devices, result = _run_listener_test(
            "kerberos",
            "KerberosPassiveListener",
            "kerberos",
            "kerberos/bruteshark_kerberos_v5_tcp.pcap",
            expect_details=["msg_type"],
        )

        with_count = [ix for ix in listener.interactions if ix.details.get("name_string_count")]
        assert len(with_count) >= 1, (
            "Expected at least one interaction with name_string_count "
            "from bruteshark_kerberos_v5_tcp.pcap"
        )


class TestKerberosEncryptedAuthenticatorCipher:
    """T1 field: kerberos.encryptedAuthenticator_cipher -- AP-REQ cipher."""

    def test_authenticator_cipher_detected(self):
        """TGS-REQ with AP-REQ should have has_authenticator_cipher."""
        # Combined TGS-REQ+AP-REQ packets in bruteshark_kerberos_v5_tcp.pcap
        listener, devices, result = _run_listener_test(
            "kerberos",
            "KerberosPassiveListener",
            "kerberos",
            "kerberos/bruteshark_kerberos_v5_tcp.pcap",
            expect_details=["msg_type"],
        )

        with_auth = [
            ix for ix in listener.interactions if ix.details.get("has_authenticator_cipher")
        ]
        assert len(with_auth) >= 1, (
            "Expected at least one interaction with has_authenticator_cipher"
        )


class TestKerberosPADataCounts:
    """T1 fields: kerberos.rEQ_SEQUENCE_OF_PA_DATA and rEP_SEQUENCE_OF_PA_DATA."""

    def test_pa_data_req_count_in_requests(self):
        """AS-REQ/TGS-REQ should have pa_data_req_count."""
        listener, devices, result = _run_listener_test(
            "kerberos",
            "KerberosPassiveListener",
            "kerberos",
            "kerberos/bruteshark_kerberos_v5_tcp.pcap",
            expect_details=["msg_type"],
        )

        with_pa_req = [ix for ix in listener.interactions if ix.details.get("pa_data_req_count")]
        assert len(with_pa_req) >= 1, "Expected pa_data_req_count in request interactions"

    def test_pa_data_rep_count_in_replies(self):
        """AS-REP/TGS-REP should have pa_data_rep_count."""
        listener, devices, result = _run_listener_test(
            "kerberos",
            "KerberosPassiveListener",
            "kerberos",
            "kerberos/bruteshark_kerberos_v5_tcp.pcap",
            expect_details=["msg_type"],
        )

        with_pa_rep = [ix for ix in listener.interactions if ix.details.get("pa_data_rep_count")]
        assert len(with_pa_rep) >= 1, "Expected pa_data_rep_count in reply interactions"


class TestKerberosEtypeCount:
    """T1 field: kerberos.kdc-req-body.etype -- requested etype count."""

    def test_requested_etype_count_in_requests(self):
        """AS-REQ should have requested_etype_count in details."""
        listener, devices, result = _run_listener_test(
            "kerberos",
            "KerberosPassiveListener",
            "kerberos",
            "kerberos/bruteshark_kerberos_v5_tcp.pcap",
            expect_details=["msg_type"],
        )

        as_req = [ix for ix in listener.interactions if ix.details.get("msg_type") == 10]
        assert len(as_req) >= 1
        with_etype_count = [ix for ix in as_req if ix.details.get("requested_etype_count")]
        assert len(with_etype_count) >= 1, "Expected requested_etype_count in AS-REQ details"


class TestKerberosChecksum:
    """T1 field: kerberos.checksum -- authenticator checksum."""

    def test_checksum_detected(self):
        """Packets with authenticator should have has_checksum."""
        listener, devices, result = _run_listener_test(
            "kerberos",
            "KerberosPassiveListener",
            "kerberos",
            "kerberos/bruteshark_kerberos_v5_tcp.pcap",
            expect_details=["msg_type"],
        )

        with_checksum = [ix for ix in listener.interactions if ix.details.get("has_checksum")]
        assert len(with_checksum) >= 1, "Expected at least one interaction with has_checksum"


class TestKerberosAddrNB:
    """T1 field: kerberos.addr_nb -- NetBIOS client hostname."""

    def test_addr_nb_extracted(self):
        """Packets with NetBIOS addresses should have client_hostname."""
        # addr_nb appears in wireshark_krb816.cap and bruteshark_kerberos_v5_udp2.pcap
        listener, devices, result = _run_listener_test(
            "kerberos",
            "KerberosPassiveListener",
            "kerberos",
            "kerberos/wireshark_krb816.cap",
            expect_details=["msg_type"],
        )

        with_hostname = [ix for ix in listener.interactions if ix.details.get("client_hostname")]
        assert len(with_hostname) >= 1, (
            "Expected at least one interaction with client_hostname from addr_nb"
        )
        # wireshark_krb816.cap has addr_nb="XP1"
        assert with_hostname[0].details["client_hostname"] == "XP1"

    def test_addr_nb_stored_in_client_hostnames(self):
        """NetBIOS hostname should be stored in listener.client_hostnames."""
        listener, devices, result = _run_listener_test(
            "kerberos",
            "KerberosPassiveListener",
            "kerberos",
            "kerberos/wireshark_krb816.cap",
            expect_details=["msg_type"],
        )

        assert len(listener.client_hostnames) >= 1, "client_hostnames should be populated"
        # Verify at least one hostname is "XP1"
        assert "XP1" in listener.client_hostnames.values(), (
            f"Expected 'XP1' in client_hostnames; got {listener.client_hostnames}"
        )

    def test_addr_nb_in_interaction_summary(self):
        """NetBIOS hostname should appear in interaction summary."""
        listener, devices, result = _run_listener_test(
            "kerberos",
            "KerberosPassiveListener",
            "kerberos",
            "kerberos/wireshark_krb816.cap",
            expect_details=["msg_type"],
        )

        with_hostname = [ix for ix in listener.interactions if "host=XP1" in (ix.summary or "")]
        assert len(with_hostname) >= 1, "Expected 'host=XP1' in interaction summary"


class TestKerberosAddressesCount:
    """T1 field: kerberos.addresses -- host address count in requests."""

    def test_addresses_count_in_details(self):
        """AS-REQ with host addresses should have addresses_count."""
        # addresses field appears in wireshark_krb816.cap and bruteshark_kerberos_v5_udp2.pcap
        listener, devices, result = _run_listener_test(
            "kerberos",
            "KerberosPassiveListener",
            "kerberos",
            "kerberos/wireshark_krb816.cap",
            expect_details=["msg_type"],
        )

        with_addrs = [ix for ix in listener.interactions if ix.details.get("addresses_count")]
        assert len(with_addrs) >= 1, "Expected at least one interaction with addresses_count"


class TestKerberosServiceNameExtraction:
    """Verify service_name is populated in interaction details."""

    def test_service_name_in_details(self):
        """Interactions should include service_name from SNameString."""
        listener, devices, result = _run_listener_test(
            "kerberos",
            "KerberosPassiveListener",
            "kerberos",
            "kerberos/bruteshark_kerberos_v5_tcp.pcap",
            expect_details=["msg_type"],
        )

        with_sname = [ix for ix in listener.interactions if ix.details.get("service_name")]
        assert len(with_sname) >= 1, "Expected service_name in interaction details"
        # Common service names include krbtgt/REALM
        assert any("krbtgt" in ix.details["service_name"] for ix in with_sname), (
            f"Expected krbtgt in service_name; got {[ix.details['service_name'] for ix in with_sname[:3]]}"
        )


class TestKerberosUDPPcap:
    """Validate field extraction works across UDP pcap fixtures.

    bruteshark_kerberos_v5_udp.pcap is a loopback capture (127.0.0.x / 0.0.0.0)
    so no devices are created, but interactions and field extraction still work.
    """

    def test_udp_error_codes_extracted(self):
        """UDP pcap should extract error_code from KRB-ERROR."""
        listener, devices, result = _run_listener_test(
            "kerberos",
            "KerberosPassiveListener",
            "kerberos",
            "kerberos/bruteshark_kerberos_v5_udp.pcap",
            min_devices=0,
            expect_details=["msg_type"],
        )

        error_interactions = [ix for ix in listener.interactions if ix.details.get("error_code")]
        assert len(error_interactions) >= 1, "Expected error_code in UDP pcap interactions"

    def test_udp_authenticator_cipher_detected(self):
        """UDP TGS-REQ should detect authenticator cipher."""
        listener, devices, result = _run_listener_test(
            "kerberos",
            "KerberosPassiveListener",
            "kerberos",
            "kerberos/bruteshark_kerberos_v5_udp.pcap",
            min_devices=0,
            expect_details=["msg_type"],
        )

        with_auth = [
            ix for ix in listener.interactions if ix.details.get("has_authenticator_cipher")
        ]
        assert len(with_auth) >= 1, "Expected authenticator cipher in UDP pcap"

    def test_udp_checksum_detected(self):
        """UDP TGS-REQ should detect checksum."""
        listener, devices, result = _run_listener_test(
            "kerberos",
            "KerberosPassiveListener",
            "kerberos",
            "kerberos/bruteshark_kerberos_v5_udp.pcap",
            min_devices=0,
            expect_details=["msg_type"],
        )

        with_checksum = [ix for ix in listener.interactions if ix.details.get("has_checksum")]
        assert len(with_checksum) >= 1, "Expected checksum in UDP pcap"


class TestKerberosV5Udp2Pcap:
    """Validate field extraction for bruteshark_kerberos_v5_udp2.pcap."""

    def test_udp2_addr_nb_extracted(self):
        """bruteshark_kerberos_v5_udp2 should have addr_nb=XP1."""
        listener, devices, result = _run_listener_test(
            "kerberos",
            "KerberosPassiveListener",
            "kerberos",
            "kerberos/bruteshark_kerberos_v5_udp2.pcap",
            expect_details=["msg_type"],
        )

        with_hostname = [ix for ix in listener.interactions if ix.details.get("client_hostname")]
        assert len(with_hostname) >= 1, "Expected client_hostname from addr_nb"
        assert with_hostname[0].details["client_hostname"] == "XP1"

    def test_udp2_addresses_count(self):
        """bruteshark_kerberos_v5_udp2 should have addresses_count."""
        listener, devices, result = _run_listener_test(
            "kerberos",
            "KerberosPassiveListener",
            "kerberos",
            "kerberos/bruteshark_kerberos_v5_udp2.pcap",
            expect_details=["msg_type"],
        )

        with_addrs = [ix for ix in listener.interactions if ix.details.get("addresses_count")]
        assert len(with_addrs) >= 1, "Expected addresses_count in details"


class TestKerberosDelegationPcap:
    """Validate field extraction for wireshark_krb_delegation.cap."""

    def test_delegation_addr_nb(self):
        """Delegation cap should have addr_nb=XP1."""
        listener, devices, result = _run_listener_test(
            "kerberos",
            "KerberosPassiveListener",
            "kerberos",
            "kerberos/wireshark_krb_delegation.cap",
            expect_details=["msg_type"],
        )

        with_hostname = [ix for ix in listener.interactions if ix.details.get("client_hostname")]
        assert len(with_hostname) >= 1, "Expected client_hostname from addr_nb"
        assert with_hostname[0].details["client_hostname"] == "XP1"

    def test_delegation_authenticator_cipher(self):
        """Delegation cap TGS-REQ should have authenticator cipher."""
        listener, devices, result = _run_listener_test(
            "kerberos",
            "KerberosPassiveListener",
            "kerberos",
            "kerberos/wireshark_krb_delegation.cap",
            expect_details=["msg_type"],
        )

        with_auth = [
            ix for ix in listener.interactions if ix.details.get("has_authenticator_cipher")
        ]
        assert len(with_auth) >= 1, "Expected authenticator cipher in delegation cap"
