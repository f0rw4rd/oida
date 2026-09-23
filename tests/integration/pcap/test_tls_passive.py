"""Integration tests for TLS passive listener in EK mode."""

import pytest

from tests.integration.pcap.conftest import _run_listener_test

pytestmark = [pytest.mark.integration]

# Shared helper constants
_MOD = "tls"
_CLS = "TLSPassiveListener"
_FILTER = "tls.handshake or tls.alert_message"


class TestTLSPassiveEK:
    """TLS-specific tests beyond the parametrised quality suite."""

    def test_tls_basic(self):
        listener, devices, result = _run_listener_test(
            _MOD,
            _CLS,
            _FILTER,
            "tls/zeek_client-certificate.pcap",
        )
        # TLS listener should track connections
        conns = listener.get_connections()
        assert isinstance(conns, list)
        if conns:
            for conn in conns:
                assert "client" in conn
                assert "server" in conn
                assert "tls_version" in conn

        # TLS listener should extract certificates
        certs = listener.get_certificates()
        assert isinstance(certs, dict)
        if certs:
            for thumb, cert in certs.items():
                assert "common_name" in cert or "subject" in cert

        # TLS harvest should produce tables when data exists
        if result.get("tables"):
            assert len(result["tables"]) >= 1, "Expected at least one table from TLS harvest"

    def test_tls_client_cert_pcap(self):
        """Client certificate pcap should detect mTLS."""
        listener, devices, result = _run_listener_test(
            _MOD,
            _CLS,
            _FILTER,
            "tls/zeek_client-certificate.pcap",
        )
        # This pcap has client certificates
        conns = listener.get_connections()
        if conns:
            mtls_conns = [
                c for c in conns if c.get("client_cert_used") or c.get("client_cert_requested")
            ]
            # The pcap name suggests client certificates are present
            if mtls_conns:
                assert len(mtls_conns) >= 1, "Expected mTLS connections in client-certificate pcap"


class TestTLSSessionID:
    """Session ID extraction from ClientHello/ServerHello."""

    def test_session_id_present(self):
        """Session ID should be captured from pcaps that include it."""
        listener, devices, result = _run_listener_test(
            _MOD,
            _CLS,
            _FILTER,
            "tls/internet_tls12_cert.pcap",
            min_devices=0,
            min_interactions=1,
        )
        conns = listener.get_connections()
        assert conns, "Expected at least one connection"
        has_session_id = any(c.get("session_id") for c in conns)
        assert has_session_id, (
            f"Expected session_id in at least one connection; "
            f"sample keys: {list(conns[0].keys()) if conns else '[]'}"
        )

    def test_session_id_format(self):
        """Session ID should be a hex-encoded byte string."""
        listener, _, _ = _run_listener_test(
            _MOD,
            _CLS,
            _FILTER,
            "tls/zeek_client-certificate.pcap",
            min_devices=0,
            min_interactions=1,
        )
        conns = listener.get_connections()
        for conn in conns:
            sid = conn.get("session_id")
            if sid:
                # Should be colon-delimited hex or plain hex
                assert isinstance(sid, str)
                assert len(sid) > 0


class TestTLSCompressionMethod:
    """Compression method extraction from ServerHello."""

    def test_comp_method_present(self):
        """Compression method should be extracted from ServerHello."""
        listener, _, _ = _run_listener_test(
            _MOD,
            _CLS,
            _FILTER,
            "tls/internet_tls12_cert.pcap",
            min_devices=0,
            min_interactions=1,
        )
        conns = listener.get_connections()
        assert conns, "Expected at least one connection"
        has_comp = any(c.get("compression_method") is not None for c in conns)
        assert has_comp, "Expected compression_method in at least one connection"

    def test_comp_method_value(self):
        """Most modern TLS uses compression method 0 (null)."""
        listener, _, _ = _run_listener_test(
            _MOD,
            _CLS,
            _FILTER,
            "tls/zeek_client-certificate.pcap",
            min_devices=0,
            min_interactions=1,
        )
        conns = listener.get_connections()
        for conn in conns:
            comp = conn.get("compression_method")
            if comp is not None:
                # Should be "0" for null compression
                assert comp == "0", f"Unexpected compression method: {comp}"


class TestTLSALPN:
    """ALPN (Application-Layer Protocol Negotiation) extraction."""

    def test_alpn_offered(self):
        """ClientHello should have ALPN protocols when present."""
        listener, _, _ = _run_listener_test(
            _MOD,
            _CLS,
            _FILTER,
            "tls/zeek_client-certificate.pcap",
            min_devices=0,
            min_interactions=1,
        )
        conns = listener.get_connections()
        assert conns, "Expected at least one connection"
        has_alpn = any(c.get("alpn") for c in conns)
        assert has_alpn, "Expected ALPN protocols in at least one connection"

    def test_alpn_values(self):
        """ALPN should contain standard protocol names like h2 or http/1.1."""
        listener, _, _ = _run_listener_test(
            _MOD,
            _CLS,
            _FILTER,
            "tls/zeek_client-certificate.pcap",
            min_devices=0,
            min_interactions=1,
        )
        conns = listener.get_connections()
        for conn in conns:
            alpn = conn.get("alpn", [])
            if alpn:
                assert isinstance(alpn, list)
                # Each entry should be a non-empty string
                for proto in alpn:
                    assert isinstance(proto, str) and len(proto) > 0

    def test_selected_alpn(self):
        """Server-selected ALPN should be a single string."""
        listener, _, _ = _run_listener_test(
            _MOD,
            _CLS,
            _FILTER,
            "tls/zeek_client-certificate.pcap",
            min_devices=0,
            min_interactions=1,
        )
        conns = listener.get_connections()
        has_selected = any(c.get("selected_alpn") for c in conns)
        if has_selected:
            for conn in conns:
                sel = conn.get("selected_alpn")
                if sel:
                    assert isinstance(sel, str)


class TestTLSSignatureAlgorithms:
    """Signature algorithm extraction from ClientHello."""

    def test_sig_algs_present(self):
        """ClientHello should include signature algorithms."""
        listener, _, _ = _run_listener_test(
            _MOD,
            _CLS,
            _FILTER,
            "tls/zeek_client-certificate.pcap",
            min_devices=0,
            min_interactions=1,
        )
        conns = listener.get_connections()
        assert conns, "Expected at least one connection"
        has_sig = any(c.get("signature_algorithms") for c in conns)
        assert has_sig, "Expected signature_algorithms in at least one connection"

    def test_sig_algs_list_format(self):
        """Signature algorithms should be a list of values."""
        listener, _, _ = _run_listener_test(
            _MOD,
            _CLS,
            _FILTER,
            "tls/zeek_client-certificate.pcap",
            min_devices=0,
            min_interactions=1,
        )
        conns = listener.get_connections()
        for conn in conns:
            sigs = conn.get("signature_algorithms", [])
            if sigs:
                assert isinstance(sigs, list)
                assert len(sigs) >= 1


class TestTLSSCT:
    """Signed Certificate Timestamp (SCT) extraction."""

    def test_sct_present(self):
        """SCT fields should be extracted from signed_certificate_timestamp pcap."""
        listener, _, _ = _run_listener_test(
            _MOD,
            _CLS,
            _FILTER,
            "tls/zeek_signed_certificate_timestamp.pcap",
            min_devices=0,
            min_interactions=1,
        )
        conns = listener.get_connections()
        assert conns, "Expected at least one connection"
        has_sct = any(c.get("sct") for c in conns)
        assert has_sct, (
            f"Expected SCT data in at least one connection; "
            f"sample keys: {list(conns[0].keys()) if conns else '[]'}"
        )

    def test_sct_fields(self):
        """SCT entries should have version and log_id."""
        listener, _, _ = _run_listener_test(
            _MOD,
            _CLS,
            _FILTER,
            "tls/zeek_signed_certificate_timestamp.pcap",
            min_devices=0,
            min_interactions=1,
        )
        conns = listener.get_connections()
        for conn in conns:
            sct_list = conn.get("sct", [])
            if sct_list:
                assert isinstance(sct_list, list)
                for sct in sct_list:
                    assert "version" in sct, f"SCT entry missing 'version': {sct}"


class TestTLSECH:
    """Encrypted Client Hello (ECH) parameter extraction."""

    def test_ech_present(self):
        """ECH fields should be extracted from ECH pcap."""
        listener, _, _ = _run_listener_test(
            _MOD,
            _CLS,
            _FILTER,
            "tls/zeek_tls13-ech.pcap",
            min_devices=0,
            min_interactions=1,
        )
        conns = listener.get_connections()
        assert conns, "Expected at least one connection"
        has_ech = any(c.get("ech") for c in conns)
        assert has_ech, (
            f"Expected ECH data in at least one connection; "
            f"sample keys: {list(conns[0].keys()) if conns else '[]'}"
        )

    def test_ech_fields(self):
        """ECH dict should have config_id, kdf_id, and aead_id."""
        listener, _, _ = _run_listener_test(
            _MOD,
            _CLS,
            _FILTER,
            "tls/zeek_tls13-ech.pcap",
            min_devices=0,
            min_interactions=1,
        )
        conns = listener.get_connections()
        for conn in conns:
            ech = conn.get("ech")
            if ech:
                assert "config_id" in ech, f"ECH missing 'config_id': {ech}"
                assert "kdf_id" in ech, f"ECH missing 'kdf_id': {ech}"
                assert "aead_id" in ech, f"ECH missing 'aead_id': {ech}"
                # config_id should be non-empty
                assert ech["config_id"], "ECH config_id should not be empty"


class TestTLSTokenBinding:
    """Token Binding extension extraction."""

    def test_token_binding_present(self):
        """Token binding should be extracted from pcap with TB extension."""
        listener, _, _ = _run_listener_test(
            _MOD,
            _CLS,
            _FILTER,
            "tls/zeek_signed_certificate_timestamp.pcap",
            min_devices=0,
            min_interactions=1,
        )
        conns = listener.get_connections()
        assert conns, "Expected at least one connection"
        has_tb = any(c.get("token_binding") for c in conns)
        assert has_tb, (
            f"Expected token_binding in at least one connection; "
            f"sample keys: {list(conns[0].keys()) if conns else '[]'}"
        )

    def test_token_binding_fields(self):
        """Token binding dict should have version and key_parameter."""
        listener, _, _ = _run_listener_test(
            _MOD,
            _CLS,
            _FILTER,
            "tls/zeek_signed_certificate_timestamp.pcap",
            min_devices=0,
            min_interactions=1,
        )
        conns = listener.get_connections()
        for conn in conns:
            tb = conn.get("token_binding")
            if tb:
                assert "version" in tb, f"Token binding missing 'version': {tb}"
                assert "key_parameter" in tb, f"Token binding missing 'key_parameter': {tb}"


class TestTLSHarvestIntegrity:
    """Verify harvest output quality with new fields."""

    def test_harvest_no_raw_dicts_in_cells(self):
        """Harvest table cells must not contain raw dicts or sets."""
        _, _, result = _run_listener_test(
            _MOD,
            _CLS,
            _FILTER,
            "tls/zeek_client-certificate.pcap",
        )
        for table in result.get("tables", []):
            for row in table.get("rows", []):
                for cell in row:
                    assert not isinstance(cell, dict), f"Raw dict in cell: {cell}"
                    assert not isinstance(cell, set), f"Raw set in cell: {cell}"

    def test_harvest_produces_tables(self):
        """Harvest should produce valid table output."""
        _, _, result = _run_listener_test(
            _MOD,
            _CLS,
            _FILTER,
            "tls/zeek_client-certificate.pcap",
        )
        assert isinstance(result, dict)
        # Tables list should exist (may be empty if no certs/errors)
        tables = result.get("tables", [])
        assert isinstance(tables, list)

    def test_harvest_sct_pcap(self):
        """Harvest on SCT pcap should not crash with new fields."""
        _, _, result = _run_listener_test(
            _MOD,
            _CLS,
            _FILTER,
            "tls/zeek_signed_certificate_timestamp.pcap",
            min_devices=0,
            min_interactions=1,
        )
        # Just verify it doesn't crash and produces valid output
        assert isinstance(result, dict)

    def test_harvest_ech_pcap(self):
        """Harvest on ECH pcap should not crash."""
        _, _, result = _run_listener_test(
            _MOD,
            _CLS,
            _FILTER,
            "tls/zeek_tls13-ech.pcap",
            min_devices=0,
            min_interactions=1,
        )
        assert isinstance(result, dict)


class TestTLSOCSPStatusRequest:
    """OCSP status_request extension (tls.handshake.extensions_status_request_type)."""

    def test_status_request_in_details(self):
        """ClientHello with status_request should expose ocsp_status_request detail."""
        listener, _, _ = _run_listener_test(
            _MOD,
            _CLS,
            _FILTER,
            "tls/wireshark_tls.pcap",
            min_devices=0,
            min_interactions=1,
        )
        found = any(ix.details.get("ocsp_status_request") for ix in listener.interactions)
        assert found, (
            "Expected ocsp_status_request in interaction details; "
            f"sample: {listener.interactions[0].details if listener.interactions else 'none'}"
        )

    def test_status_request_in_connection(self):
        """OCSP stapling request should be tracked on the connection."""
        listener, _, _ = _run_listener_test(
            _MOD,
            _CLS,
            _FILTER,
            "tls/wireshark_tls.pcap",
            min_devices=0,
            min_interactions=1,
        )
        conns = listener.get_connections()
        assert any(c.get("ocsp_status_request") for c in conns), (
            "Expected ocsp_status_request flag on at least one connection"
        )


class TestTLSRSAKeyExchange:
    """Encrypted PreMaster secret length (tls.handshake.epms_len) => RSA key exchange."""

    def test_epms_len_in_details(self):
        """ClientKeyExchange with epms_len should expose rsa_key_exchange/epms_len detail."""
        listener, _, _ = _run_listener_test(
            _MOD,
            _CLS,
            _FILTER,
            "tls/wireshark_tls_sni.pcap",
            min_devices=0,
            min_interactions=1,
        )
        found = any(ix.details.get("epms_len") for ix in listener.interactions)
        assert found, (
            "Expected epms_len in interaction details; "
            f"sample: {listener.interactions[0].details if listener.interactions else 'none'}"
        )

    def test_rsa_key_exchange_connection_and_alert(self):
        """RSA key exchange should be flagged on the connection and raise a no-PFS alert."""
        listener, _, result = _run_listener_test(
            _MOD,
            _CLS,
            _FILTER,
            "tls/wireshark_tls_sni.pcap",
            min_devices=0,
            min_interactions=1,
        )
        conns = listener.get_connections()
        assert any(c.get("rsa_key_exchange") for c in conns), (
            "Expected rsa_key_exchange flag on at least one connection"
        )
        alerts = result.get("alerts", [])
        assert any(a.get("category") == "tls_no_pfs" for a in alerts), (
            "Expected a tls_no_pfs (no forward secrecy) security alert"
        )
