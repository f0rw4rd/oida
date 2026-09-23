"""Integration tests for BFD passive listener in EK mode.

Tests cover:
- T1 field extraction: bfd.version, bfd.auth.len
- EK field name fixes: bfd.sta (not flags_sta), bfd.diag (not flags_diag)
- T2 field extraction: discriminators, detect_time_multiplier, message_length
- Credential extraction: Simple Password and Keyed MD5
- Device data enrichment: version, state, discriminator
- Harvest output: operations table shape, credentials table
"""

import pytest

from tests.integration.pcap.conftest import _run_listener_test

pytestmark = [pytest.mark.integration]


class TestBFDPassiveEK:
    """BFD-specific field extraction tests using EK-mode pcap fixtures."""

    # -- Basic smoke test --

    def test_bfd_basic_smoke(self):
        """Smoke test: listener discovers devices and records interactions."""
        listener, devices, result = _run_listener_test(
            "bfd",
            "BFDPassiveListener",
            "bfd",
            "bfd/generated_bfd.pcap",
            min_devices=2,
            min_interactions=2,
        )
        assert isinstance(result, dict), "Expected harvest to return a dict"

    # -- T1 field: bfd.version --

    def test_bfd_version_extracted(self):
        """T1 field 'bfd.version' extracted into interaction details."""
        listener, _, _ = _run_listener_test(
            "bfd",
            "BFDPassiveListener",
            "bfd",
            "bfd/generated_bfd.pcap",
            expect_details=["version"],
        )
        for ix in listener.interactions:
            version = ix.details.get("version")
            assert version is not None, "version missing from interaction details"
            assert version != "?", "version should not be '?' for valid BFD packets"
            assert version == 1, f"Expected BFD version 1, got {version}"

    def test_bfd_version_in_device_data(self):
        """T1 field 'bfd.version' stored in device bfd_passive_data."""
        _, devices, _ = _run_listener_test(
            "bfd",
            "BFDPassiveListener",
            "bfd",
            "bfd/generated_bfd.pcap",
        )
        for dev in devices.values():
            data = getattr(dev, "bfd_passive_data", None)
            if data and data.get("role") == "sender":
                assert data.get("version") == 1, (
                    f"Expected version 1 in device data, got {data.get('version')}"
                )
                break
        else:
            pytest.fail("No sender device found with bfd_passive_data")

    # -- T1 field: bfd.auth.len --

    def test_bfd_auth_len_extracted(self):
        """T1 field 'bfd.auth.len' extracted into interaction details."""
        listener, _, _ = _run_listener_test(
            "bfd",
            "BFDPassiveListener",
            "bfd",
            "bfd/generated_bfd.pcap",
            expect_details=["auth_len"],
        )
        auth_ixs = [ix for ix in listener.interactions if ix.details.get("auth_type", 0) > 0]
        assert len(auth_ixs) >= 1, "Expected authenticated interactions"
        for ix in auth_ixs:
            auth_len = ix.details.get("auth_len")
            assert auth_len is not None, "auth_len missing from authenticated interaction"
            assert auth_len != "?", "auth_len should not be '?' for valid auth packets"
            assert int(auth_len) > 0, f"auth_len should be > 0, got {auth_len}"

    def test_bfd_auth_len_simple_password(self):
        """Simple Password auth (type 1) has auth_len = 12 (header + 'secret123')."""
        listener, _, _ = _run_listener_test(
            "bfd",
            "BFDPassiveListener",
            "bfd",
            "bfd/generated_bfd.pcap",
        )
        simple_ixs = [ix for ix in listener.interactions if ix.details.get("auth_type") == 1]
        assert simple_ixs, "Expected Simple Password interaction"
        assert simple_ixs[0].details["auth_len"] == "12", (
            f"Expected auth_len 12 for Simple Password, got {simple_ixs[0].details['auth_len']}"
        )

    def test_bfd_auth_len_keyed_md5(self):
        """Keyed MD5 auth (type 2) has auth_len = 24 (header + 16-byte digest)."""
        listener, _, _ = _run_listener_test(
            "bfd",
            "BFDPassiveListener",
            "bfd",
            "bfd/generated_bfd.pcap",
        )
        md5_ixs = [ix for ix in listener.interactions if ix.details.get("auth_type") == 2]
        assert md5_ixs, "Expected Keyed MD5 interaction"
        assert md5_ixs[0].details["auth_len"] == "24", (
            f"Expected auth_len 24 for Keyed MD5, got {md5_ixs[0].details['auth_len']}"
        )

    def test_bfd_auth_len_empty_for_no_auth(self):
        """Non-authenticated packets have empty auth_len, not '?'."""
        # If the pcap had non-auth packets they'd have auth_len=""
        # Both packets in fixture are authenticated, so just verify
        # they all have a non-empty auth_len
        listener, _, _ = _run_listener_test(
            "bfd",
            "BFDPassiveListener",
            "bfd",
            "bfd/generated_bfd.pcap",
        )
        for ix in listener.interactions:
            if ix.details.get("auth_type", 0) == 0:
                # Non-auth packet: auth_len should be empty
                assert ix.details.get("auth_len") == "", (
                    "auth_len should be empty for non-auth packets"
                )

    # -- EK field name fix: bfd.sta (was broken as flags_sta) --

    def test_bfd_state_extracted(self):
        """EK field 'sta' (not 'flags_sta') correctly extracts BFD state."""
        listener, _, _ = _run_listener_test(
            "bfd",
            "BFDPassiveListener",
            "bfd",
            "bfd/generated_bfd.pcap",
            expect_details=["state_name"],
        )
        for ix in listener.interactions:
            state = ix.details.get("state")
            state_name = ix.details.get("state_name")
            assert state is not None, "state missing from interaction details"
            assert state >= 0, f"state should be >= 0 (not broken -1 default), got {state}"
            assert state_name not in (None, "", "?"), (
                f"state_name should be a valid name, got {state_name!r}"
            )
            # Both packets in fixture are state 3 = Up
            assert state == 3, f"Expected state 3 (Up), got {state}"
            assert state_name == "Up", f"Expected 'Up', got {state_name!r}"

    def test_bfd_state_in_operation_string(self):
        """BFD state name appears in the interaction operation string."""
        listener, _, _ = _run_listener_test(
            "bfd",
            "BFDPassiveListener",
            "bfd",
            "bfd/generated_bfd.pcap",
        )
        for ix in listener.interactions:
            assert "BFD Up" == ix.operation, f"Expected operation 'BFD Up', got {ix.operation!r}"

    # -- EK field name fix: bfd.diag (was broken as flags_diag) --

    def test_bfd_diag_extracted(self):
        """EK field 'diag' (not 'flags_diag') correctly extracts diagnostic code."""
        listener, _, _ = _run_listener_test(
            "bfd",
            "BFDPassiveListener",
            "bfd",
            "bfd/generated_bfd.pcap",
        )
        for ix in listener.interactions:
            diag = ix.details.get("diag")
            diag_name = ix.details.get("diag_name")
            assert diag is not None, "diag missing from interaction details"
            assert diag >= 0, f"diag should be >= 0 (not broken -1 default), got {diag}"
            assert diag_name not in (None, "?"), (
                f"diag_name should not be None or '?', got {diag_name!r}"
            )
            # Both packets have diag=0 = "No Diagnostic"
            assert diag == 0, f"Expected diag 0, got {diag}"
            assert diag_name == "No Diagnostic", f"Expected 'No Diagnostic', got {diag_name!r}"

    # -- T2 fields: discriminators --

    def test_bfd_my_discriminator_extracted(self):
        """T2 field 'bfd.my_discriminator' extracted into interaction details."""
        listener, _, _ = _run_listener_test(
            "bfd",
            "BFDPassiveListener",
            "bfd",
            "bfd/generated_bfd.pcap",
        )
        discs = set()
        for ix in listener.interactions:
            my_disc = ix.details.get("my_discriminator")
            assert my_disc, f"my_discriminator should not be empty, got {my_disc!r}"
            discs.add(my_disc)
        # Fixture has discriminators 1 and 2
        assert "1" in discs, f"Expected discriminator '1' in {discs}"
        assert "2" in discs, f"Expected discriminator '2' in {discs}"

    def test_bfd_your_discriminator_extracted(self):
        """T2 field 'bfd.your_discriminator' extracted into interaction details."""
        listener, _, _ = _run_listener_test(
            "bfd",
            "BFDPassiveListener",
            "bfd",
            "bfd/generated_bfd.pcap",
        )
        for ix in listener.interactions:
            your_disc = ix.details.get("your_discriminator")
            assert your_disc, f"your_discriminator should not be empty, got {your_disc!r}"

    def test_bfd_discriminator_in_device_data(self):
        """Discriminator stored in device bfd_passive_data."""
        _, devices, _ = _run_listener_test(
            "bfd",
            "BFDPassiveListener",
            "bfd",
            "bfd/generated_bfd.pcap",
        )
        discs = set()
        for dev in devices.values():
            data = getattr(dev, "bfd_passive_data", None)
            if data and data.get("discriminator"):
                discs.add(data["discriminator"])
        assert discs, "Expected at least one device with discriminator in bfd_passive_data"
        assert "1" in discs or "2" in discs, f"Expected discriminator values, got {discs}"

    # -- T2 fields: detect_time_multiplier --

    def test_bfd_detect_time_multiplier_extracted(self):
        """T2 field 'bfd.detect_time_multiplier' extracted into interaction details."""
        listener, _, _ = _run_listener_test(
            "bfd",
            "BFDPassiveListener",
            "bfd",
            "bfd/generated_bfd.pcap",
        )
        for ix in listener.interactions:
            mult = ix.details.get("detect_time_multiplier")
            assert mult, f"detect_time_multiplier should not be empty, got {mult!r}"
            assert mult == "3", f"Expected detect_time_multiplier '3', got {mult}"

    def test_bfd_detect_time_multiplier_in_device_data(self):
        """detect_time_multiplier stored in device bfd_passive_data."""
        _, devices, _ = _run_listener_test(
            "bfd",
            "BFDPassiveListener",
            "bfd",
            "bfd/generated_bfd.pcap",
        )
        for dev in devices.values():
            data = getattr(dev, "bfd_passive_data", None)
            if data and data.get("detect_time_multiplier"):
                assert data["detect_time_multiplier"] == "3"
                break
        else:
            pytest.fail("No device has detect_time_multiplier in bfd_passive_data")

    # -- T2 field: message_length --

    def test_bfd_message_length_extracted(self):
        """T2 field 'bfd.message_length' extracted into interaction details."""
        listener, _, _ = _run_listener_test(
            "bfd",
            "BFDPassiveListener",
            "bfd",
            "bfd/generated_bfd.pcap",
        )
        lengths = set()
        for ix in listener.interactions:
            msg_len = ix.details.get("message_length")
            assert msg_len, f"message_length should not be empty, got {msg_len!r}"
            lengths.add(msg_len)
        # Simple Password: 36 bytes, Keyed MD5: 48 bytes
        assert "36" in lengths, f"Expected message_length '36', got {lengths}"
        assert "48" in lengths, f"Expected message_length '48', got {lengths}"

    # -- Credential extraction --

    def test_bfd_simple_password_credential(self):
        """Simple Password auth (type 1) extracts plaintext password."""
        listener, _, _ = _run_listener_test(
            "bfd",
            "BFDPassiveListener",
            "bfd",
            "bfd/generated_bfd.pcap",
        )
        assert listener.credentials, "Expected at least one credential"
        simple_creds = [c for c in listener.credentials if c.auth_type == 1]
        assert simple_creds, "Expected Simple Password credential"
        cred = simple_creds[0]
        assert cred.credential_type == "plaintext"
        assert cred.password == "secret123", f"Expected 'secret123', got {cred.password!r}"
        assert cred.auth_type_name == "Simple Password"
        assert cred.key_id == 1

    def test_bfd_keyed_md5_credential(self):
        """Keyed MD5 auth (type 2) extracts hash credential."""
        listener, _, _ = _run_listener_test(
            "bfd",
            "BFDPassiveListener",
            "bfd",
            "bfd/generated_bfd.pcap",
        )
        md5_creds = [c for c in listener.credentials if c.auth_type == 2]
        assert md5_creds, "Expected Keyed MD5 credential"
        cred = md5_creds[0]
        assert cred.credential_type == "hash"
        assert cred.auth_type_name == "Keyed MD5"
        assert cred.key_id == 1

    def test_bfd_credential_canonical_fields(self):
        """BFD credential exposes canonical field names for scanner compatibility."""
        listener, _, _ = _run_listener_test(
            "bfd",
            "BFDPassiveListener",
            "bfd",
            "bfd/generated_bfd.pcap",
        )
        assert listener.credentials, "Expected credentials"
        # Test Simple Password credential
        simple_cred = next(c for c in listener.credentials if c.auth_type == 1)
        assert simple_cred.server_ip, "server_ip should not be empty"
        assert simple_cred.client_ip, "client_ip should not be empty"
        assert simple_cred.username == "secret123", "username should be the password"
        assert simple_cred.auth_method == "Simple Password"
        assert simple_cred.credential_type == "plaintext"
        assert simple_cred.hash_value == "", "hash_value should be empty for plaintext"

        # Test Keyed MD5 credential
        md5_cred = next(c for c in listener.credentials if c.auth_type == 2)
        assert md5_cred.credential_type == "hash"
        assert md5_cred.auth_method == "Keyed MD5"

    def test_bfd_credentials_summary(self):
        """get_credentials_summary() returns scanner-compatible dicts."""
        listener, _, _ = _run_listener_test(
            "bfd",
            "BFDPassiveListener",
            "bfd",
            "bfd/generated_bfd.pcap",
        )
        summaries = listener.get_credentials_summary()
        assert len(summaries) >= 2, f"Expected >= 2 credential summaries, got {len(summaries)}"
        for s in summaries:
            assert s.get("protocol") == "BFD"
            assert "auth_method" in s, f"Missing auth_method: {s}"
            assert "credential_type" in s, f"Missing credential_type: {s}"
            assert "username" in s, f"Missing username: {s}"
            assert "server_ip" in s, f"Missing server_ip: {s}"
            assert "client_ip" in s, f"Missing client_ip: {s}"

    def test_bfd_credential_dedup(self):
        """Duplicate credentials (same auth_type, password, key_id, IPs) are deduped."""
        listener, _, _ = _run_listener_test(
            "bfd",
            "BFDPassiveListener",
            "bfd",
            "bfd/generated_bfd.pcap",
        )
        # The fixture has exactly 2 packets with different auth types
        # so there should be exactly 2 credentials
        assert len(listener.credentials) == 2, (
            f"Expected exactly 2 credentials (one per auth type), got {len(listener.credentials)}"
        )

    # -- Device data quality --

    def test_bfd_both_endpoints_tracked(self):
        """Both sender and receiver BFD peers are tracked as devices."""
        _, devices, _ = _run_listener_test(
            "bfd",
            "BFDPassiveListener",
            "bfd",
            "bfd/generated_bfd.pcap",
            min_devices=2,
        )
        all_ips = set()
        for dev in devices.values():
            all_ips.update(dev.ip_addresses)
        assert "10.0.0.1" in all_ips, f"Expected 10.0.0.1 in devices, got {all_ips}"
        assert "10.0.0.2" in all_ips, f"Expected 10.0.0.2 in devices, got {all_ips}"

    def test_bfd_device_data_populated(self):
        """Discovered devices have bfd_passive_data with expected fields."""
        _, devices, _ = _run_listener_test(
            "bfd",
            "BFDPassiveListener",
            "bfd",
            "bfd/generated_bfd.pcap",
        )
        for dev in devices.values():
            data = getattr(dev, "bfd_passive_data", None)
            assert data is not None, f"Device {dev.ip} missing bfd_passive_data"
            assert data.get("role") in ("sender", "receiver"), (
                f"Expected role sender/receiver, got {data.get('role')}"
            )
            assert data.get("protocol") == "BFD/UDP", (
                f"Expected protocol 'BFD/UDP', got {data.get('protocol')}"
            )

    def test_bfd_sender_device_enriched(self):
        """Sender devices have version, state, discriminator in bfd_passive_data."""
        _, devices, _ = _run_listener_test(
            "bfd",
            "BFDPassiveListener",
            "bfd",
            "bfd/generated_bfd.pcap",
        )
        sender_data = [
            dev.bfd_passive_data
            for dev in devices.values()
            if hasattr(dev, "bfd_passive_data") and dev.bfd_passive_data.get("role") == "sender"
        ]
        assert sender_data, "Expected at least one sender device"
        for data in sender_data:
            assert data.get("version") == 1, f"Expected version 1, got {data.get('version')}"
            assert data.get("state") == "Up", f"Expected state 'Up', got {data.get('state')}"
            assert data.get("discriminator"), "discriminator should not be empty"
            assert data.get("detect_time_multiplier"), "detect_time_multiplier should not be empty"

    # -- Harvest output quality --

    def test_bfd_protocol_columns_set(self):
        """PROTOCOL_COLUMNS is set on the listener class."""
        from oida.pcap.bfd import BFDPassiveListener

        assert BFDPassiveListener.PROTOCOL_COLUMNS
        expected_cols = (
            "ver",
            "state",
            "diag",
            "my_disc",
            "your_disc",
            "auth_type",
            "auth_len",
            "min_tx",
            "min_rx",
        )
        assert BFDPassiveListener.PROTOCOL_COLUMNS == expected_cols

    def test_bfd_format_protocol_columns_count(self):
        """_format_protocol_columns output must match PROTOCOL_COLUMNS length."""
        from oida.pcap.bfd import BFDPassiveListener

        listener, _, _ = _run_listener_test(
            "bfd",
            "BFDPassiveListener",
            "bfd",
            "bfd/generated_bfd.pcap",
        )

        expected = len(BFDPassiveListener.PROTOCOL_COLUMNS)
        for ix in listener.interactions:
            row = listener._format_protocol_columns(ix)
            assert len(row) == expected, f"Row has {len(row)} columns, expected {expected}: {row}"

    def test_bfd_format_protocol_columns_content(self):
        """_format_protocol_columns rows contain the correct extracted values."""
        listener, _, _ = _run_listener_test(
            "bfd",
            "BFDPassiveListener",
            "bfd",
            "bfd/generated_bfd.pcap",
        )

        # Find the Simple Password interaction (10.0.0.1 -> 10.0.0.2)
        simple_ixs = [ix for ix in listener.interactions if ix.details.get("auth_type") == 1]
        assert simple_ixs, "Expected Simple Password interaction"
        row = listener._format_protocol_columns(simple_ixs[0])
        assert row[0] == 1, f"Expected version 1, got {row[0]}"  # Ver
        assert row[1] == "Up", f"Expected state 'Up', got {row[1]}"  # State
        assert row[5] == "Simple Password", f"Expected 'Simple Password', got {row[5]}"  # Auth Type
        assert row[6] == "12", f"Expected auth_len '12', got {row[6]}"  # Auth Len

        # Find the Keyed MD5 interaction (10.0.0.2 -> 10.0.0.1)
        md5_ixs = [ix for ix in listener.interactions if ix.details.get("auth_type") == 2]
        assert md5_ixs, "Expected Keyed MD5 interaction"
        row = listener._format_protocol_columns(md5_ixs[0])
        assert row[5] == "Keyed MD5", f"Expected 'Keyed MD5', got {row[5]}"
        assert row[6] == "24", f"Expected auth_len '24', got {row[6]}"

    def test_bfd_harvest_no_raw_dicts_in_cells(self):
        """No raw dicts or sets in any table cell."""
        _, _, result = _run_listener_test(
            "bfd",
            "BFDPassiveListener",
            "bfd",
            "bfd/generated_bfd.pcap",
        )
        for table in result.get("tables", []):
            for row in table.get("rows", []):
                for cell in row:
                    assert not isinstance(cell, dict), f"Raw dict in {table['title']} cell: {cell}"
                    assert not isinstance(cell, set), f"Raw set in {table['title']} cell: {cell}"

    # -- Interaction recording quality --

    def test_bfd_interaction_flow_id(self):
        """Interactions have non-empty flow_id for stream correlation."""
        listener, _, _ = _run_listener_test(
            "bfd",
            "BFDPassiveListener",
            "bfd",
            "bfd/generated_bfd.pcap",
        )
        for ix in listener.interactions:
            assert ix.flow_id, f"flow_id should not be empty, got {ix.flow_id!r}"

    def test_bfd_interaction_endpoints(self):
        """Interactions have correct source/destination IPs."""
        listener, _, _ = _run_listener_test(
            "bfd",
            "BFDPassiveListener",
            "bfd",
            "bfd/generated_bfd.pcap",
        )
        src_ips = {ix.src_ip for ix in listener.interactions}
        dst_ips = {ix.dst_ip for ix in listener.interactions}
        assert "10.0.0.1" in src_ips, f"Expected 10.0.0.1 in sources, got {src_ips}"
        assert "10.0.0.2" in src_ips, f"Expected 10.0.0.2 in sources, got {src_ips}"
        assert "10.0.0.1" in dst_ips, f"Expected 10.0.0.1 in dests, got {dst_ips}"
        assert "10.0.0.2" in dst_ips, f"Expected 10.0.0.2 in dests, got {dst_ips}"

    def test_bfd_interaction_all_details_populated(self):
        """Every interaction has all expected detail keys populated."""
        listener, _, _ = _run_listener_test(
            "bfd",
            "BFDPassiveListener",
            "bfd",
            "bfd/generated_bfd.pcap",
        )
        required_keys = [
            "version",
            "state",
            "state_name",
            "diag",
            "diag_name",
            "my_discriminator",
            "your_discriminator",
            "detect_time_multiplier",
            "message_length",
            "auth_type",
            "auth_type_name",
            "min_tx",
            "min_rx",
        ]
        for ix in listener.interactions:
            for key in required_keys:
                assert key in ix.details, f"Missing detail key '{key}' in interaction: {ix.details}"
