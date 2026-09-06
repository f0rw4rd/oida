"""Integration tests for Telnet passive listener in EK mode.

Covers:
- Credential extraction (plaintext login/password)
- T1 auth negotiation fields (auth_cmd, auth_type, auth_mod_enc, auth_data)
- T2 option negotiation fields (cmd, subcmd, naws, string_subopt, auth modifiers)
- Device enrichment (auth_types, terminal info, options_negotiated)
- Harvest output quality
"""

import pytest

from .conftest import _run_listener_test

pytestmark = [pytest.mark.integration]


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------


def _make_telnet_listener(pcap_subpath, **kwargs):
    """Shortcut: run the telnet listener against a pcap fixture."""
    return _run_listener_test(
        "telnet",
        "TelnetPassiveListener",
        "telnet",
        pcap_subpath,
        **kwargs,
    )


# ---------------------------------------------------------------------------
# Credential extraction (existing + expanded)
# ---------------------------------------------------------------------------


class TestTelnetCredentials:
    """Credential extraction from Telnet login flows."""

    def test_credentials_extracted_bruteshark(self):
        """bruteshark_telnet.pcap: character-mode login flow."""
        listener, devices, result = _make_telnet_listener(
            "telnet/bruteshark_telnet.pcap",
        )

        creds = listener.get_credentials_summary()
        assert len(creds) >= 1, f"Expected >= 1 credential, got {len(creds)}"
        for cred in creds:
            assert cred["protocol"] == "Telnet"
            assert cred["credential_type"] == "plaintext"
            assert cred["username"], "Credential missing username"
            assert "password" in cred, "Credential missing password key"
            assert cred["server_ip"], "Credential missing server_ip"
            assert cred["client_ip"], "Credential missing client_ip"

        # Session tracking
        assert len(listener._sessions) >= 1, "No Telnet sessions tracked"

    def test_credentials_extracted_raw2(self):
        """credslayer_telnet_raw2.pcap: NTLM auth fails, then plaintext login."""
        listener, devices, result = _make_telnet_listener(
            "telnet/credslayer_telnet_raw2.pcap",
        )

        creds = listener.get_credentials_summary()
        assert len(creds) >= 1, f"Expected >= 1 credential, got {len(creds)}"
        cred = creds[0]
        assert cred["username"], "Missing username in raw2 credential"
        assert cred["password"], "Missing password in raw2 credential"
        assert cred["auth_method"] == "Telnet"

    def test_credential_dedup(self):
        """Same credential should not appear twice."""
        listener, devices, result = _make_telnet_listener(
            "telnet/bruteshark_telnet.pcap",
        )
        creds = listener.get_credentials_summary()
        # Build set of (user, pass, server)
        seen = set()
        for c in creds:
            key = (c["username"], c["password"], c["server_ip"])
            assert key not in seen, f"Duplicate credential: {key}"
            seen.add(key)


# ---------------------------------------------------------------------------
# T1: Authentication negotiation fields (RFC 2941)
# ---------------------------------------------------------------------------


class TestTelnetAuthNegotiation:
    """T1 field extraction: auth_cmd, auth_type, auth_mod_enc, auth_data."""

    def test_auth_cmd_extracted(self):
        """telnet.auth.cmd field extracted and resolved to name."""
        listener, devices, result = _make_telnet_listener(
            "telnet/credslayer_telnet_raw2.pcap",
        )
        auth_ixs = [ix for ix in listener.interactions if ix.details.get("auth_cmd")]
        assert len(auth_ixs) >= 1, "No interactions with auth_cmd detail"
        auth_cmds = {ix.details["auth_cmd"] for ix in auth_ixs}
        # SEND, IS, REPLY are expected in the NTLM exchange
        assert auth_cmds & {"SEND", "IS", "REPLY"}, (
            f"Expected SEND/IS/REPLY auth commands, got {auth_cmds}"
        )

    def test_auth_type_extracted(self):
        """telnet.auth.type field extracted and resolved to NTLM."""
        listener, devices, result = _make_telnet_listener(
            "telnet/credslayer_telnet_raw2.pcap",
        )
        auth_ixs = [ix for ix in listener.interactions if ix.details.get("auth_type")]
        assert len(auth_ixs) >= 1, "No interactions with auth_type detail"
        auth_types = {ix.details["auth_type"] for ix in auth_ixs}
        assert "NTLM" in auth_types, f"Expected NTLM auth type, got {auth_types}"

    def test_auth_mod_enc_extracted(self):
        """telnet.auth.mod.enc field extracted and resolved."""
        listener, devices, result = _make_telnet_listener(
            "telnet/credslayer_telnet_raw2.pcap",
        )
        auth_ixs = [ix for ix in listener.interactions if ix.details.get("auth_mod_enc")]
        assert len(auth_ixs) >= 1, "No interactions with auth_mod_enc detail"
        enc_vals = {ix.details["auth_mod_enc"] for ix in auth_ixs}
        assert "ENCRYPT_OFF" in enc_vals, f"Expected ENCRYPT_OFF, got {enc_vals}"

    def test_auth_data_extracted(self):
        """telnet.auth.data field extracted (NTLM blobs)."""
        listener, devices, result = _make_telnet_listener(
            "telnet/credslayer_telnet_raw2.pcap",
        )
        auth_ixs = [ix for ix in listener.interactions if ix.details.get("auth_data")]
        assert len(auth_ixs) >= 1, "No interactions with auth_data detail"
        # NTLM signature is 4e:54:4c:4d:53:53:50 ("NTLMSSP")
        has_ntlm = any("4e:54:4c:4d:53:53:50" in ix.details["auth_data"] for ix in auth_ixs)
        assert has_ntlm, "auth_data should contain NTLMSSP signature"

    def test_auth_modifiers_who_how_cred_fwd(self):
        """T2 auth modifier booleans extracted in interaction details."""
        listener, devices, result = _make_telnet_listener(
            "telnet/credslayer_telnet_raw2.pcap",
        )
        auth_ixs = [ix for ix in listener.interactions if ix.details.get("auth_cmd")]
        assert len(auth_ixs) >= 1
        # At least one interaction should have auth_mod_who
        has_who = any("auth_mod_who" in ix.details for ix in auth_ixs)
        assert has_who, (
            f"No auth interaction has auth_mod_who; sample details: {auth_ixs[0].details}"
        )

    def test_session_tracks_auth_types(self):
        """Session object accumulates auth types seen."""
        listener, devices, result = _make_telnet_listener(
            "telnet/credslayer_telnet_raw2.pcap",
        )
        for _key, sess in listener._sessions.items():
            if sess.auth_types_seen:
                assert "NTLM" in sess.auth_types_seen
                return
        pytest.fail("No session has auth_types_seen populated")


# ---------------------------------------------------------------------------
# T2: Option negotiation fields
# ---------------------------------------------------------------------------


class TestTelnetOptionNegotiation:
    """T2 field extraction: cmd, subcmd, NAWS, string_subopt, options."""

    def test_naws_width_height_extracted(self):
        """telnet.naws_subopt.width/height stored on session and in details."""
        listener, devices, result = _make_telnet_listener(
            "telnet/bruteshark_telnet.pcap",
        )
        # Session should have terminal dimensions
        has_naws = False
        for _key, sess in listener._sessions.items():
            if sess.terminal_width > 0 and sess.terminal_height > 0:
                has_naws = True
                assert sess.terminal_width == 80, f"Expected width 80, got {sess.terminal_width}"
                assert sess.terminal_height == 24, f"Expected height 24, got {sess.terminal_height}"
        assert has_naws, "No session has NAWS dimensions"

        # Interaction details should contain naws_width
        naws_ixs = [ix for ix in listener.interactions if ix.details.get("naws_width")]
        assert len(naws_ixs) >= 1, "No interaction has naws_width detail"

    def test_string_subopt_terminal_type(self):
        """telnet.string_subopt.value used to populate terminal_type."""
        listener, devices, result = _make_telnet_listener(
            "telnet/bruteshark_telnet.pcap",
        )
        has_terminal = False
        for _key, sess in listener._sessions.items():
            if sess.terminal_type:
                has_terminal = True
                # Should contain something meaningful (e.g. "xterm")
                assert len(sess.terminal_type) >= 2
        assert has_terminal, "No session has terminal_type"

        # Check interaction details
        str_ixs = [ix for ix in listener.interactions if ix.details.get("string_subopt")]
        assert len(str_ixs) >= 1, "No interaction has string_subopt detail"

    def test_cmd_subcmd_in_interaction_details(self):
        """telnet.cmd and telnet.subcmd stored in interaction details."""
        listener, devices, result = _make_telnet_listener(
            "telnet/bruteshark_telnet.pcap",
        )
        cmd_ixs = [ix for ix in listener.interactions if ix.details.get("cmd")]
        assert len(cmd_ixs) >= 1, "No interaction has cmd detail"

        subcmd_ixs = [ix for ix in listener.interactions if ix.details.get("subcmd")]
        assert len(subcmd_ixs) >= 1, "No interaction has subcmd detail"

    def test_options_negotiated_tracked(self):
        """Session accumulates option names from subcmd values."""
        listener, devices, result = _make_telnet_listener(
            "telnet/bruteshark_telnet.pcap",
        )
        for _key, sess in listener._sessions.items():
            if sess.options_negotiated:
                # We expect at least NAWS and Terminal Type
                assert "NAWS" in sess.options_negotiated, (
                    f"Missing NAWS, got {sess.options_negotiated}"
                )
                assert "Terminal Type" in sess.options_negotiated, (
                    f"Missing Terminal Type, got {sess.options_negotiated}"
                )
                return
        pytest.fail("No session has options_negotiated populated")


# ---------------------------------------------------------------------------
# Device enrichment
# ---------------------------------------------------------------------------


class TestTelnetDeviceEnrichment:
    """Server/client device data includes auth and terminal info."""

    def test_server_device_auth_types(self):
        """Server device enriched with auth_types from negotiation."""
        listener, devices, result = _make_telnet_listener(
            "telnet/credslayer_telnet_raw2.pcap",
        )
        server_devs = [
            d
            for d in devices.values()
            if hasattr(d, "telnet_passive_data")
            and d.telnet_passive_data
            and d.telnet_passive_data.get("role") == "server"
        ]
        assert len(server_devs) >= 1, "No server device found"
        pdata = server_devs[0].telnet_passive_data
        assert "auth_types" in pdata, f"Server missing auth_types; keys: {list(pdata.keys())}"
        assert "NTLM" in pdata["auth_types"], f"NTLM not in auth_types: {pdata['auth_types']}"

    def test_server_device_auth_encryption(self):
        """Server device enriched with auth_encryption from negotiation."""
        listener, devices, result = _make_telnet_listener(
            "telnet/credslayer_telnet_raw2.pcap",
        )
        server_devs = [
            d
            for d in devices.values()
            if hasattr(d, "telnet_passive_data")
            and d.telnet_passive_data
            and d.telnet_passive_data.get("role") == "server"
        ]
        assert len(server_devs) >= 1
        pdata = server_devs[0].telnet_passive_data
        assert "auth_encryption" in pdata, "Server missing auth_encryption"
        assert pdata["auth_encryption"] == "ENCRYPT_OFF"

    def test_server_device_terminal_info(self):
        """Server device enriched with terminal_type and terminal_size."""
        listener, devices, result = _make_telnet_listener(
            "telnet/bruteshark_telnet.pcap",
        )
        server_devs = [
            d
            for d in devices.values()
            if hasattr(d, "telnet_passive_data")
            and d.telnet_passive_data
            and d.telnet_passive_data.get("role") == "server"
        ]
        assert len(server_devs) >= 1, "No server device found"
        pdata = server_devs[0].telnet_passive_data
        assert "terminal_type" in pdata, f"Server missing terminal_type; keys: {list(pdata.keys())}"
        assert "terminal_size" in pdata, f"Server missing terminal_size; keys: {list(pdata.keys())}"
        assert pdata["terminal_size"] == "80x24"

    def test_server_device_options_negotiated(self):
        """Server device enriched with negotiated option names."""
        listener, devices, result = _make_telnet_listener(
            "telnet/bruteshark_telnet.pcap",
        )
        server_devs = [
            d
            for d in devices.values()
            if hasattr(d, "telnet_passive_data")
            and d.telnet_passive_data
            and d.telnet_passive_data.get("role") == "server"
        ]
        assert len(server_devs) >= 1
        pdata = server_devs[0].telnet_passive_data
        assert "options_negotiated" in pdata, "Server missing options_negotiated"
        opts = pdata["options_negotiated"]
        assert "NAWS" in opts, f"NAWS not in options: {opts}"
        assert "Terminal Type" in opts, f"Terminal Type not in options: {opts}"

    def test_both_endpoints_tracked(self):
        """Both server and client devices are created."""
        listener, devices, result = _make_telnet_listener(
            "telnet/bruteshark_telnet.pcap",
        )
        roles = set()
        for d in devices.values():
            if hasattr(d, "telnet_passive_data") and d.telnet_passive_data:
                roles.add(d.telnet_passive_data.get("role"))
        assert "server" in roles, f"No server device; roles: {roles}"
        assert "client" in roles, f"No client device; roles: {roles}"

    def test_client_device_tracks_servers(self):
        """Client device tracks list of servers accessed."""
        listener, devices, result = _make_telnet_listener(
            "telnet/bruteshark_telnet.pcap",
        )
        client_devs = [
            d
            for d in devices.values()
            if hasattr(d, "telnet_passive_data")
            and d.telnet_passive_data
            and d.telnet_passive_data.get("role") == "client"
        ]
        assert len(client_devs) >= 1, "No client device"
        pdata = client_devs[0].telnet_passive_data
        assert "servers_accessed" in pdata
        assert len(pdata["servers_accessed"]) >= 1


# ---------------------------------------------------------------------------
# Harvest output quality
# ---------------------------------------------------------------------------


class TestTelnetHarvest:
    """harvest() produces valid output."""

    def test_harvest_returns_valid_dict(self):
        """harvest() returns a valid dict (no custom tables for Telnet)."""
        listener, devices, result = _make_telnet_listener(
            "telnet/bruteshark_telnet.pcap",
            check_harvest=True,
        )
        assert isinstance(result, dict)


# ---------------------------------------------------------------------------
# Multiple pcap fixtures
# ---------------------------------------------------------------------------


class TestTelnetMultiplePcaps:
    """Test different pcap fixtures for robustness."""

    def test_bruteshark_char_mode(self):
        """bruteshark_telnet_char.pcap: character-mode variant."""
        listener, devices, result = _make_telnet_listener(
            "telnet/bruteshark_telnet_char.pcap",
        )
        assert len(devices) >= 1
        # Should have negotiation interactions
        negot_ixs = [
            ix
            for ix in listener.interactions
            if "Negotiation" in ix.operation or "Data" in ix.operation
        ]
        assert len(negot_ixs) >= 1

    def test_bruteshark_line_mode(self):
        """bruteshark_telnet_line.pcap: line-mode variant."""
        listener, devices, result = _make_telnet_listener(
            "telnet/bruteshark_telnet_line.pcap",
        )
        assert len(devices) >= 1

    def test_credslayer_telnet(self):
        """credslayer_telnet.pcap: basic login capture."""
        listener, devices, result = _make_telnet_listener(
            "telnet/credslayer_telnet.pcap",
        )
        assert len(devices) >= 1

    def test_credslayer_raw(self):
        """credslayer_telnet_raw.pcap: raw telnet login."""
        listener, devices, result = _make_telnet_listener(
            "telnet/credslayer_telnet_raw.pcap",
        )
        assert len(devices) >= 1

    def test_credslayer_cooked(self):
        """credslayer_telnet_cooked.pcap: cooked mode capture."""
        listener, devices, result = _make_telnet_listener(
            "telnet/credslayer_telnet_cooked.pcap",
        )
        assert len(devices) >= 1
