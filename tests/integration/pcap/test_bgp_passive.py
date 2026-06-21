"""Integration tests for BGP passive listener in EK mode.

Tests cover all T1 tshark field extractions:
- OPEN: open_myas, open_holdtime, open_version, open_identifier,
        cap_orf_fqdn_hostname, cap_orf_fqdn_domain_name,
        cap_gr_timers_restart_flag, cap_bgpsec_version
- UPDATE: update_path_attribute_origin, update_path_attribute_community_as,
          update_path_attribute_community_value,
          update_path_attribute_bgpsec_sb_algo_id
- NOTIFICATION: notify_major_error, notify_minor_error_cease
- Credential extraction from open_opt_param_auth
"""

import pytest

from .conftest import _run_listener_test

pytestmark = [pytest.mark.integration]


class TestBGPGeneratedPcap:
    """Tests against generated_bgp.pcap (OPEN with auth + KEEPALIVE)."""

    def test_bgp_basic_extraction(self):
        """Verify basic packet processing and device/interaction creation."""
        listener, devices, result = _run_listener_test(
            "bgp",
            "BGPPassiveListener",
            "bgp",
            "bgp/generated_bgp.pcap",
            min_devices=2,
            min_interactions=2,
        )
        # OPEN + KEEPALIVE should produce interactions
        ops = {ix.operation for ix in listener.interactions}
        assert any("OPEN" in op for op in ops), f"Expected OPEN interaction, got: {ops}"
        assert any("KEEPALIVE" in op for op in ops), f"Expected KEEPALIVE interaction, got: {ops}"

    def test_bgp_open_as_number(self):
        """T1 field: open_myas -- AS number from OPEN message."""
        listener, devices, result = _run_listener_test(
            "bgp",
            "BGPPassiveListener",
            "bgp",
            "bgp/generated_bgp.pcap",
            min_devices=2,
            min_interactions=1,
            expect_details=["as_number"],
        )
        # Find the OPEN interaction and verify AS number
        open_ixs = [ix for ix in listener.interactions if ix.details.get("msg_type") == "1"]
        assert len(open_ixs) >= 1, "Expected at least one OPEN interaction"
        assert open_ixs[0].details["as_number"] == "65001"

    def test_bgp_open_hold_time(self):
        """T1 field: open_holdtime -- hold time from OPEN message."""
        listener, devices, result = _run_listener_test(
            "bgp",
            "BGPPassiveListener",
            "bgp",
            "bgp/generated_bgp.pcap",
            min_devices=2,
            min_interactions=1,
            expect_details=["hold_time"],
        )
        open_ixs = [ix for ix in listener.interactions if ix.details.get("msg_type") == "1"]
        assert open_ixs[0].details["hold_time"] == "180"

    def test_bgp_open_version(self):
        """T1 field: open_version -- BGP version from OPEN message."""
        listener, devices, result = _run_listener_test(
            "bgp",
            "BGPPassiveListener",
            "bgp",
            "bgp/generated_bgp.pcap",
            min_devices=2,
            min_interactions=1,
            expect_details=["version"],
        )
        open_ixs = [ix for ix in listener.interactions if ix.details.get("msg_type") == "1"]
        assert open_ixs[0].details["version"] == "4"

    def test_bgp_open_router_id(self):
        """T2 field: open_identifier -- BGP Router ID from OPEN message."""
        listener, devices, result = _run_listener_test(
            "bgp",
            "BGPPassiveListener",
            "bgp",
            "bgp/generated_bgp.pcap",
            min_devices=2,
            min_interactions=1,
            expect_details=["router_id"],
        )
        open_ixs = [ix for ix in listener.interactions if ix.details.get("msg_type") == "1"]
        assert open_ixs[0].details["router_id"] == "10.0.0.1"

    def test_bgp_credential_extraction(self):
        """Credential extraction from open_opt_param_auth."""
        listener, devices, result = _run_listener_test(
            "bgp",
            "BGPPassiveListener",
            "bgp",
            "bgp/generated_bgp.pcap",
            min_devices=2,
            min_interactions=1,
        )
        assert len(listener.credentials) >= 1, "Expected at least one credential"
        cred = listener.credentials[0]
        assert cred.auth_data == "01:02:03:04"
        # Verify canonical field names
        assert cred.username == "01:02:03:04"
        assert cred.server_ip != ""
        assert cred.client_ip != ""
        assert cred.auth_method == "BGP Auth"
        assert cred.credential_type == "plaintext"

    def test_bgp_credentials_summary(self):
        """get_credentials_summary() returns scanner-compatible dicts."""
        listener, devices, result = _run_listener_test(
            "bgp",
            "BGPPassiveListener",
            "bgp",
            "bgp/generated_bgp.pcap",
            min_devices=2,
            min_interactions=1,
        )
        creds = listener.get_credentials_summary()
        assert len(creds) >= 1
        c = creds[0]
        assert c["protocol"] == "BGP"
        assert c["credential_type"] == "plaintext"
        assert c["username"] == "01:02:03:04"
        assert "server_ip" in c
        assert "client_ip" in c

    def test_bgp_device_enrichment(self):
        """Device passive data includes AS number and router ID."""
        listener, devices, result = _run_listener_test(
            "bgp",
            "BGPPassiveListener",
            "bgp",
            "bgp/generated_bgp.pcap",
            min_devices=2,
            min_interactions=1,
        )
        # The sender of the OPEN (10.0.0.1) should have AS + router ID
        sender_dev = None
        for key, dev in devices.items():
            data = getattr(dev, "bgp_passive_data", {})
            if data.get("as_number") == "65001":
                sender_dev = dev
                break
        assert sender_dev is not None, "Expected device with AS 65001"
        data = sender_dev.bgp_passive_data
        assert data["router_id"] == "10.0.0.1"
        assert data["protocol"] == "BGP/TCP"

    def test_bgp_harvest_returns_dict(self):
        """harvest() returns a dict."""
        listener, devices, result = _run_listener_test(
            "bgp",
            "BGPPassiveListener",
            "bgp",
            "bgp/generated_bgp.pcap",
            min_devices=2,
            min_interactions=1,
        )
        assert isinstance(result, dict), "harvest() should return a dict"


class TestBGPWiresharkPcapng:
    """Tests against wireshark_bgp.pcapng (OPEN + UPDATE with communities)."""

    def test_bgp_hostname_extraction(self):
        """T1 field: cap_orf_fqdn_hostname -- peer hostname from OPEN caps."""
        listener, devices, result = _run_listener_test(
            "bgp",
            "BGPPassiveListener",
            "bgp",
            "bgp/wireshark_bgp.pcapng",
            min_devices=2,
            min_interactions=2,
        )
        open_ixs = [ix for ix in listener.interactions if ix.details.get("msg_type") == "1"]
        assert len(open_ixs) >= 1, "Expected OPEN interactions"
        hostnames = [ix.details.get("hostname") for ix in open_ixs if ix.details.get("hostname")]
        assert len(hostnames) >= 1, f"Expected hostname in OPEN caps, got: {open_ixs[0].details}"
        assert "ubuntu01" in hostnames

    def test_bgp_graceful_restart_flag(self):
        """T1 field: cap_gr_timers_restart_flag -- Graceful Restart from OPEN."""
        listener, devices, result = _run_listener_test(
            "bgp",
            "BGPPassiveListener",
            "bgp",
            "bgp/wireshark_bgp.pcapng",
            min_devices=2,
            min_interactions=2,
        )
        open_ixs = [ix for ix in listener.interactions if ix.details.get("msg_type") == "1"]
        gr_flags = [ix.details.get("gr_restart_flag") for ix in open_ixs]
        gr_flags = [f for f in gr_flags if f is not None]
        assert len(gr_flags) >= 1, "Expected Graceful Restart flag in OPEN"

    def test_bgp_update_origin(self):
        """T1 field: update_path_attribute_origin -- origin attr from UPDATE."""
        listener, devices, result = _run_listener_test(
            "bgp",
            "BGPPassiveListener",
            "bgp",
            "bgp/wireshark_bgp.pcapng",
            min_devices=2,
            min_interactions=2,
        )
        update_ixs = [ix for ix in listener.interactions if ix.details.get("msg_type") == "2"]
        assert len(update_ixs) >= 1, "Expected at least one UPDATE interaction"
        origins = [ix.details.get("origin") for ix in update_ixs if ix.details.get("origin")]
        assert len(origins) >= 1, f"Expected origin in UPDATE, got: {update_ixs[0].details}"
        assert "IGP" in origins, f"Expected IGP origin, got: {origins}"

    def test_bgp_update_community(self):
        """T1 fields: community_as + community_value from UPDATE."""
        listener, devices, result = _run_listener_test(
            "bgp",
            "BGPPassiveListener",
            "bgp",
            "bgp/wireshark_bgp.pcapng",
            min_devices=2,
            min_interactions=2,
        )
        update_ixs = [ix for ix in listener.interactions if ix.details.get("msg_type") == "2"]
        assert len(update_ixs) >= 1
        communities = [
            ix.details.get("community") for ix in update_ixs if ix.details.get("community")
        ]
        assert len(communities) >= 1, f"Expected community in UPDATE, got: {update_ixs[0].details}"
        assert "321:654" in communities, f"Expected 321:654 community, got: {communities}"

    def test_bgp_update_nlri_prefixes(self):
        """NLRI prefix extraction from UPDATE messages."""
        listener, devices, result = _run_listener_test(
            "bgp",
            "BGPPassiveListener",
            "bgp",
            "bgp/wireshark_bgp.pcapng",
            min_devices=2,
            min_interactions=2,
        )
        update_ixs = [ix for ix in listener.interactions if ix.details.get("msg_type") == "2"]
        nlri = [
            ix.details.get("nlri_prefixes") for ix in update_ixs if ix.details.get("nlri_prefixes")
        ]
        assert len(nlri) >= 1, "Expected NLRI prefixes in UPDATE"
        # Should contain the advertised networks
        assert any("10.50.0.0" in n for n in nlri), f"Expected 10.50.0.0 in NLRI, got: {nlri}"

    def test_bgp_update_as_path(self):
        """AS path segment extraction from UPDATE messages."""
        listener, devices, result = _run_listener_test(
            "bgp",
            "BGPPassiveListener",
            "bgp",
            "bgp/wireshark_bgp.pcapng",
            min_devices=2,
            min_interactions=2,
        )
        update_ixs = [ix for ix in listener.interactions if ix.details.get("msg_type") == "2"]
        as_paths = [ix.details.get("as_path") for ix in update_ixs if ix.details.get("as_path")]
        assert len(as_paths) >= 1, "Expected AS path in UPDATE"

    def test_bgp_device_hostname_enrichment(self):
        """Device passive data includes hostname from FQDN capability."""
        listener, devices, result = _run_listener_test(
            "bgp",
            "BGPPassiveListener",
            "bgp",
            "bgp/wireshark_bgp.pcapng",
            min_devices=2,
            min_interactions=2,
        )
        hostnames_found = []
        for key, dev in devices.items():
            data = getattr(dev, "bgp_passive_data", {})
            if data.get("hostname"):
                hostnames_found.append(data["hostname"])
        assert len(hostnames_found) >= 1, "Expected hostname in device data"
        assert "ubuntu01" in hostnames_found

    def test_bgp_device_graceful_restart_enrichment(self):
        """Device passive data includes graceful_restart flag."""
        listener, devices, result = _run_listener_test(
            "bgp",
            "BGPPassiveListener",
            "bgp",
            "bgp/wireshark_bgp.pcapng",
            min_devices=2,
            min_interactions=2,
        )
        gr_found = False
        for key, dev in devices.items():
            data = getattr(dev, "bgp_passive_data", {})
            if "graceful_restart" in data:
                gr_found = True
                break
        assert gr_found, "Expected graceful_restart flag in device data"

    def test_bgp_open_detail_summary_in_interactions(self):
        """OPEN interaction details contain hostname info."""
        listener, devices, result = _run_listener_test(
            "bgp",
            "BGPPassiveListener",
            "bgp",
            "bgp/wireshark_bgp.pcapng",
            min_devices=2,
            min_interactions=2,
        )
        open_ixs = [ix for ix in listener.interactions if ix.details.get("msg_type") == "1"]
        assert len(open_ixs) >= 1
        hostnames = [ix.details.get("hostname") for ix in open_ixs if ix.details.get("hostname")]
        assert len(hostnames) >= 1, "Expected hostname in OPEN interaction details"


class TestBGPShutdownPcap:
    """Tests against wireshark_bgp_shutdown.pcap (NOTIFICATION messages)."""

    def test_bgp_notification_major_error(self):
        """T1 field: notify_major_error -- NOTIFICATION major error code."""
        listener, devices, result = _run_listener_test(
            "bgp",
            "BGPPassiveListener",
            "bgp",
            "bgp/wireshark_bgp_shutdown.pcap",
            min_devices=2,
            min_interactions=1,
        )
        notif_ixs = [ix for ix in listener.interactions if ix.details.get("msg_type") == "3"]
        assert len(notif_ixs) >= 1, "Expected NOTIFICATION interaction"
        d = notif_ixs[0].details
        assert d["notify_major"] == "6", f"Expected major error 6 (Cease), got: {d}"
        assert d["notify_major_name"] == "Cease"

    def test_bgp_notification_minor_error_cease(self):
        """T1 field: notify_minor_error_cease -- Cease subcode."""
        listener, devices, result = _run_listener_test(
            "bgp",
            "BGPPassiveListener",
            "bgp",
            "bgp/wireshark_bgp_shutdown.pcap",
            min_devices=2,
            min_interactions=1,
        )
        notif_ixs = [ix for ix in listener.interactions if ix.details.get("msg_type") == "3"]
        assert len(notif_ixs) >= 1
        d = notif_ixs[0].details
        assert d["notify_minor_cease"] == "2", f"Expected minor 2 (Admin Shutdown), got: {d}"
        assert d["notify_minor_cease_name"] == "Administrative Shutdown"

    def test_bgp_notification_communication_message(self):
        """Shutdown communication string from NOTIFICATION (RFC 8203)."""
        listener, devices, result = _run_listener_test(
            "bgp",
            "BGPPassiveListener",
            "bgp",
            "bgp/wireshark_bgp_shutdown.pcap",
            min_devices=2,
            min_interactions=1,
        )
        notif_ixs = [ix for ix in listener.interactions if ix.details.get("msg_type") == "3"]
        assert len(notif_ixs) >= 1
        msg = notif_ixs[0].details.get("notify_message", "")
        assert "maintenance" in msg.lower(), f"Expected shutdown message, got: {msg}"
        assert "TICKET-1-24824294" in msg

    def test_bgp_notification_detail_summary(self):
        """NOTIFICATION detail column contains error description."""
        listener, devices, result = _run_listener_test(
            "bgp",
            "BGPPassiveListener",
            "bgp",
            "bgp/wireshark_bgp_shutdown.pcap",
            min_devices=2,
            min_interactions=1,
        )
        notif_ixs = [ix for ix in listener.interactions if ix.details.get("msg_type") == "3"]
        assert len(notif_ixs) >= 1
        detail = notif_ixs[0].details.get("detail", "")
        assert "Cease" in detail, f"Expected 'Cease' in detail, got: {detail}"
        assert "Administrative Shutdown" in detail


class TestBGPsecPcap:
    """Tests against wireshark_bgpsec.pcap (BGPsec capability + signatures)."""

    def test_bgpsec_version_extraction(self):
        """T1 field: cap_bgpsec_version -- BGPsec version from OPEN caps."""
        listener, devices, result = _run_listener_test(
            "bgp",
            "BGPPassiveListener",
            "bgp",
            "bgp/wireshark_bgpsec.pcap",
            min_devices=2,
            min_interactions=2,
        )
        open_ixs = [ix for ix in listener.interactions if ix.details.get("msg_type") == "1"]
        assert len(open_ixs) >= 1
        versions = [
            ix.details.get("bgpsec_version")
            for ix in open_ixs
            if ix.details.get("bgpsec_version") is not None
        ]
        assert len(versions) >= 1, f"Expected bgpsec_version in OPEN, got: {open_ixs[0].details}"

    def test_bgpsec_algo_id_extraction(self):
        """T1 field: bgpsec_sb_algo_id -- BGPsec signature algorithm from UPDATE."""
        listener, devices, result = _run_listener_test(
            "bgp",
            "BGPPassiveListener",
            "bgp",
            "bgp/wireshark_bgpsec.pcap",
            min_devices=2,
            min_interactions=2,
        )
        update_ixs = [ix for ix in listener.interactions if ix.details.get("msg_type") == "2"]
        assert len(update_ixs) >= 1, "Expected UPDATE interactions in bgpsec pcap"
        algos = [
            ix.details.get("bgpsec_algo_id")
            for ix in update_ixs
            if ix.details.get("bgpsec_algo_id")
        ]
        assert len(algos) >= 1, f"Expected bgpsec_algo_id in UPDATE, got: {update_ixs[0].details}"
        assert "1" in algos, f"Expected algo_id=1, got: {algos}"

    def test_bgpsec_hostname_in_open(self):
        """FQDN hostname present in BGPsec OPEN messages."""
        listener, devices, result = _run_listener_test(
            "bgp",
            "BGPPassiveListener",
            "bgp",
            "bgp/wireshark_bgpsec.pcap",
            min_devices=2,
            min_interactions=2,
        )
        open_ixs = [ix for ix in listener.interactions if ix.details.get("msg_type") == "1"]
        hostnames = [ix.details.get("hostname") for ix in open_ixs if ix.details.get("hostname")]
        assert len(hostnames) >= 1, "Expected hostname in bgpsec OPEN"
        expected = {"bgpd1", "bgpd2"}
        assert set(hostnames) & expected, f"Expected bgpd1/bgpd2, got: {hostnames}"

    def test_bgpsec_device_enrichment(self):
        """Devices from BGPsec pcap have bgpsec_version in passive data."""
        listener, devices, result = _run_listener_test(
            "bgp",
            "BGPPassiveListener",
            "bgp",
            "bgp/wireshark_bgpsec.pcap",
            min_devices=2,
            min_interactions=2,
        )
        bgpsec_devices = []
        for key, dev in devices.items():
            data = getattr(dev, "bgp_passive_data", {})
            if "bgpsec_version" in data:
                bgpsec_devices.append(data)
        assert len(bgpsec_devices) >= 1, "Expected device with bgpsec_version"

    def test_bgpsec_update_origin(self):
        """UPDATE origin attribute present in BGPsec traffic."""
        listener, devices, result = _run_listener_test(
            "bgp",
            "BGPPassiveListener",
            "bgp",
            "bgp/wireshark_bgpsec.pcap",
            min_devices=2,
            min_interactions=2,
        )
        update_ixs = [ix for ix in listener.interactions if ix.details.get("msg_type") == "2"]
        origins = [ix.details.get("origin") for ix in update_ixs if ix.details.get("origin")]
        assert len(origins) >= 1, "Expected origin in BGPsec UPDATE"
        assert "IGP" in origins


class TestBGPCredentialCompatibility:
    """Verify BGPCredential dataclass scanner compatibility."""

    def test_credential_canonical_fields(self):
        """All canonical credential fields are directly accessible."""
        from oida.pcap.bgp import BGPCredential

        cred = BGPCredential(
            auth_data="test_auth",
            peer_ip="10.0.0.1",
            local_ip="10.0.0.2",
        )
        # These must be accessible without fallback chains
        assert cred.username == "test_auth"
        assert cred.password == "test_auth"
        assert cred.server_ip == "10.0.0.1"
        assert cred.client_ip == "10.0.0.2"
        assert cred.auth_method == "BGP Auth"
        assert cred.credential_type == "plaintext"

    def test_credential_deduplication(self):
        """Same credential is not added twice."""
        listener, devices, result = _run_listener_test(
            "bgp",
            "BGPPassiveListener",
            "bgp",
            "bgp/generated_bgp.pcap",
            min_devices=2,
            min_interactions=1,
        )
        # generated_bgp has one OPEN with auth -- should have exactly 1 cred
        assert len(listener.credentials) == 1


class TestBGPInteractionTable:
    """Verify PROTOCOL_COLUMNS and _format_protocol_columns wiring."""

    def test_protocol_columns_set(self):
        """PROTOCOL_COLUMNS is set on the listener class."""
        from oida.pcap.bgp import BGPPassiveListener

        assert BGPPassiveListener.PROTOCOL_COLUMNS
        assert "type" in BGPPassiveListener.PROTOCOL_COLUMNS

    def test_format_protocol_columns_count(self):
        """_format_protocol_columns output must match PROTOCOL_COLUMNS length."""
        from oida.pcap.bgp import BGPPassiveListener

        listener, devices, result = _run_listener_test(
            "bgp",
            "BGPPassiveListener",
            "bgp",
            "bgp/wireshark_bgp.pcapng",
            min_devices=2,
            min_interactions=2,
        )

        expected = len(BGPPassiveListener.PROTOCOL_COLUMNS)
        for ix in listener.interactions:
            row = listener._format_protocol_columns(ix)
            assert len(row) == expected, f"Row has {len(row)} cols, expected {expected}: {row}"

    def test_no_raw_dicts_in_format_output(self):
        """No raw dicts or sets in _format_protocol_columns output."""
        listener, devices, result = _run_listener_test(
            "bgp",
            "BGPPassiveListener",
            "bgp",
            "bgp/wireshark_bgp.pcapng",
            min_devices=2,
            min_interactions=2,
        )
        for ix in listener.interactions:
            row = listener._format_protocol_columns(ix)
            for cell in row:
                assert not isinstance(cell, dict), f"Raw dict in cell: {cell}"
                assert not isinstance(cell, set), f"Raw set in cell: {cell}"
                assert not isinstance(cell, list), f"Raw list in cell: {cell}"

    def test_update_community_in_interactions(self):
        """UPDATE interactions contain community info."""
        listener, devices, result = _run_listener_test(
            "bgp",
            "BGPPassiveListener",
            "bgp",
            "bgp/wireshark_bgp.pcapng",
            min_devices=2,
            min_interactions=2,
        )
        update_ixs = [ix for ix in listener.interactions if ix.details.get("msg_type") == "2"]
        assert len(update_ixs) >= 1, "Expected UPDATE interactions"
        communities = [
            ix.details.get("community") for ix in update_ixs if ix.details.get("community")
        ]
        assert len(communities) >= 1, "Expected community in UPDATE interactions"
