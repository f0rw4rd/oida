"""Integration tests for IEC 104 passive listener in EK mode.

Tests the IEC104PassiveListener against various pcap fixtures covering:
- Monitoring data (type IDs 1-40): single-point, double-point, float, etc.
- Control commands (type IDs 45-64): single/double/regulating step commands
- System commands (100-107): interrogation, clock sync, etc.
- U-frame handling: STARTDT, STOPDT, TESTFR
- Value extraction: per-IOA values for all supported type categories
- Quality flags: SIQ, DIQ, QDS quality descriptors
- Session tracking: controlling/controlled station roles
- Device passive data: common addresses, IOA ranges, type counts
- Malware traffic: Industroyer2 IEC 104 attack patterns
"""

import pytest

from .conftest import _run_listener_test

pytestmark = [pytest.mark.integration]


# ========================================================================
# Baseline Tests (baselines pcap - commands + monitoring)
# ========================================================================


class TestIEC104PassiveEK:
    """IEC 104-specific tests beyond the parametrized quality suite."""

    def test_iec104_sessions_and_type_ids(self):
        """Sessions must be populated with type IDs and common addresses."""
        listener, devices, result = _run_listener_test(
            "iec104",
            "IEC104PassiveListener",
            "iec60870_104",
            "iec104/emreekin_iec104_baselines.pcap",
            expect_details=["type_id", "type_name", "common_address", "rw"],
        )

        # A1: sessions populated
        assert len(listener.sessions) >= 1, (
            f"Expected >= 1 IEC 104 session, got {len(listener.sessions)}"
        )

        # A2: session has type IDs and common addresses
        for session in listener.sessions.values():
            assert session.type_ids, "Session has no type_ids"

        # A3: passive_data on at least one device
        has_data = any(
            hasattr(d, "iec104_passive_data") and d.iec104_passive_data for d in devices.values()
        )
        assert has_data, "No device has iec104_passive_data"

        # A4: harvest returns a dict (tables are now built centrally by scanner)
        assert isinstance(result, dict)


# ========================================================================
# Value Extraction Tests
# ========================================================================


class TestIEC104Values:
    """Test value extraction from IEC 104 interactions."""

    def test_baselines_interactions_have_values(self):
        """Baselines pcap has command data, at least some must have values."""
        listener, devices, result = _run_listener_test(
            "iec104",
            "IEC104PassiveListener",
            "iec60870_104",
            "iec104/emreekin_iec104_baselines.pcap",
            expect_details=["type_id"],
        )

        interactions_with_values = [ix for ix in listener.interactions if ix.details.get("values")]
        assert len(interactions_with_values) > 0, (
            "No interactions have values; expected value extraction for command/monitoring type IDs"
        )

    def test_value_types_are_strings(self):
        """All extracted values must be strings (human-readable format)."""
        listener, devices, result = _run_listener_test(
            "iec104",
            "IEC104PassiveListener",
            "iec60870_104",
            "iec104/emreekin_iec104_baselines.pcap",
            expect_details=["type_id"],
        )

        for ix in listener.interactions:
            values = ix.details.get("values", [])
            if values:
                assert isinstance(values, list), f"values should be a list, got {type(values)}"
                for v in values:
                    assert isinstance(v, str), f"value should be a string, got {type(v)}: {v}"

    def test_command_values_specific(self):
        """Baselines pcap has known command values we can assert against."""
        listener, devices, result = _run_listener_test(
            "iec104",
            "IEC104PassiveListener",
            "iec60870_104",
            "iec104/emreekin_iec104_baselines.pcap",
            expect_details=["type_id"],
        )

        # Collect all values across interactions
        all_values = []
        for ix in listener.interactions:
            vals = ix.details.get("values", [])
            all_values.extend(vals)

        all_values_str = " ".join(all_values).lower()

        # Baselines pcap contains known command values:
        # C_SC_NA_1 with ON, C_DC_NA_1 with OFF/ON, setpoints with 3.14, 123, etc.
        assert "on" in all_values_str or "off" in all_values_str, (
            f"Expected ON/OFF in command values; got: {all_values[:10]}"
        )

    def test_setpoint_float_values(self):
        """Baselines pcap has C_SE_NC_1 (float setpoint) with 3.14 and 9.87."""
        listener, devices, result = _run_listener_test(
            "iec104",
            "IEC104PassiveListener",
            "iec60870_104",
            "iec104/emreekin_iec104_baselines.pcap",
            expect_details=["type_id"],
        )

        float_values = []
        for ix in listener.interactions:
            if ix.details.get("type_name") == "C_SE_NC_1":
                float_values.extend(ix.details.get("values", []))

        assert len(float_values) > 0, "No C_SE_NC_1 setpoint values found"
        # Check for known values
        found_314 = any("3.14" in v for v in float_values)
        found_987 = any("9.87" in v for v in float_values)
        assert found_314 or found_987, (
            f"Expected 3.14 or 9.87 in float setpoint values; got: {float_values}"
        )

    def test_scaled_setpoint_values(self):
        """Baselines pcap has C_SE_NB_1 (scaled setpoint) with 123 and 456."""
        listener, devices, result = _run_listener_test(
            "iec104",
            "IEC104PassiveListener",
            "iec60870_104",
            "iec104/emreekin_iec104_baselines.pcap",
            expect_details=["type_id"],
        )

        scaled_values = []
        for ix in listener.interactions:
            if ix.details.get("type_name") == "C_SE_NB_1":
                scaled_values.extend(ix.details.get("values", []))

        assert len(scaled_values) > 0, "No C_SE_NB_1 scaled setpoint values found"
        found_123 = any("123" in v for v in scaled_values)
        found_456 = any("456" in v for v in scaled_values)
        assert found_123 or found_456, (
            f"Expected 123 or 456 in scaled setpoint values; got: {scaled_values}"
        )

    def test_type58_59_monitoring_values(self):
        """Type58_59 pcap has monitoring data (M_SP_TB_1, M_DP_TB_1) with ON/OFF."""
        listener, devices, result = _run_listener_test(
            "iec104",
            "IEC104PassiveListener",
            "iec60870_104",
            "iec104/emreekin_iec104_type58_59.pcap",
            expect_details=["type_id"],
        )

        monitoring_values = []
        for ix in listener.interactions:
            if ix.details.get("rw") == "read":
                monitoring_values.extend(ix.details.get("values", []))

        assert len(monitoring_values) > 0, "No monitoring values found in type58_59 pcap"
        # M_SP_TB_1 and M_DP_TB_1 produce ON/OFF/INTERMEDIATE/INDETERMINATE
        all_vals = " ".join(monitoring_values).upper()
        assert any(term in all_vals for term in ["ON", "OFF", "INTERMEDIATE", "INDETERMINATE"]), (
            f"Expected monitoring status values; got: {monitoring_values}"
        )


# ========================================================================
# Quality Flag Tests
# ========================================================================


class TestIEC104Quality:
    """Test quality flag extraction from IEC 104 interactions."""

    def test_type58_59_has_quality(self):
        """Type58_59 pcap has monitoring types (M_SP_TB_1, M_DP_TB_1) with quality."""
        listener, devices, result = _run_listener_test(
            "iec104",
            "IEC104PassiveListener",
            "iec60870_104",
            "iec104/emreekin_iec104_type58_59.pcap",
            expect_details=["type_id"],
        )

        interactions_with_quality = [
            ix for ix in listener.interactions if ix.details.get("quality") is not None
        ]
        # M_SP_TB_1 (type 30) and M_DP_TB_1 (type 31) have SIQ/DIQ quality
        assert len(interactions_with_quality) > 0, (
            "No interactions have quality flags; monitoring types should have quality"
        )

    def test_quality_is_list_of_strings(self):
        """Quality flags must be a list of strings per IOA."""
        listener, devices, result = _run_listener_test(
            "iec104",
            "IEC104PassiveListener",
            "iec60870_104",
            "iec104/emreekin_iec104_type58_59.pcap",
            expect_details=["type_id"],
        )

        for ix in listener.interactions:
            quality = ix.details.get("quality")
            if quality is not None:
                assert isinstance(quality, list), (
                    f"quality should be a list, got {type(quality)}: {quality}"
                )
                for q in quality:
                    assert isinstance(q, str), (
                        f"quality flag should be a string, got {type(q)}: {q}"
                    )

    def test_quality_flags_contain_known_abbreviations(self):
        """Quality flags must use known abbreviations (IV, NT, SB, BL, OV) or be empty."""
        listener, devices, result = _run_listener_test(
            "iec104",
            "IEC104PassiveListener",
            "iec60870_104",
            "iec104/emreekin_iec104_type58_59.pcap",
            expect_details=["type_id"],
        )

        known_flags = {"IV", "NT", "SB", "BL", "OV"}
        for ix in listener.interactions:
            for q in ix.details.get("quality", []):
                if q:  # non-empty quality string
                    # Quality strings are pipe-separated (e.g. "IV|NT")
                    parts = q.split("|")
                    for part in parts:
                        assert part in known_flags, (
                            f"Unknown quality flag {part!r}; expected one of {known_flags}"
                        )

    def test_ndpi_pcap_has_quality(self):
        """NDPI pcap has M_ME_TF_1 (float with time) which has QDS quality."""
        listener, devices, result = _run_listener_test(
            "iec104",
            "IEC104PassiveListener",
            "iec60870_104",
            "iec104/ndpi_iec104.pcap",
            expect_details=["type_id"],
        )

        # M_ME_TF_1 (type 36) has QDS quality flags
        quality_interactions = [
            ix for ix in listener.interactions if ix.details.get("quality") is not None
        ]
        assert len(quality_interactions) > 0, "NDPI pcap with M_ME_TF_1 should have quality flags"


# ========================================================================
# Common Address Tests
# ========================================================================


class TestIEC104CommonAddress:
    """Test common address (ASDU address) extraction."""

    def test_baselines_common_address_is_nonnegative_int(self):
        """Common addresses in interactions must be non-negative integers."""
        listener, devices, result = _run_listener_test(
            "iec104",
            "IEC104PassiveListener",
            "iec60870_104",
            "iec104/emreekin_iec104_baselines.pcap",
            expect_details=["common_address"],
        )

        for ix in listener.interactions:
            ca = ix.details.get("common_address")
            if ca is not None:
                assert isinstance(ca, int), f"common_address should be int, got {type(ca)}: {ca}"
                assert ca >= 0, f"common_address should be non-negative, got {ca}"

    def test_baselines_common_address_value(self):
        """Baselines pcap uses common address 10."""
        listener, devices, result = _run_listener_test(
            "iec104",
            "IEC104PassiveListener",
            "iec60870_104",
            "iec104/emreekin_iec104_baselines.pcap",
            expect_details=["common_address"],
        )

        common_addresses = set()
        for ix in listener.interactions:
            ca = ix.details.get("common_address")
            if ca is not None and ca > 0:
                common_addresses.add(ca)

        assert 10 in common_addresses, (
            f"Expected common address 10 in baselines pcap; found: {common_addresses}"
        )

    def test_session_common_addresses_nonempty(self):
        """Sessions must have non-empty common_addresses sets."""
        listener, devices, result = _run_listener_test(
            "iec104",
            "IEC104PassiveListener",
            "iec60870_104",
            "iec104/emreekin_iec104_baselines.pcap",
            expect_details=["type_id"],
        )

        for key, session in listener.sessions.items():
            assert len(session.common_addresses) > 0, f"Session {key} has empty common_addresses"


# ========================================================================
# IOA (Information Object Address) Tests
# ========================================================================


class TestIEC104IOA:
    """Test IOA (Information Object Address) extraction."""

    def test_interactions_have_ioa(self):
        """At least some interactions must have IOA in details."""
        listener, devices, result = _run_listener_test(
            "iec104",
            "IEC104PassiveListener",
            "iec60870_104",
            "iec104/emreekin_iec104_baselines.pcap",
            expect_details=["type_id"],
        )

        interactions_with_ioa = [
            ix for ix in listener.interactions if ix.details.get("ioa") is not None
        ]
        assert len(interactions_with_ioa) > 0, "No interactions have IOA in details"

    def test_ioa_values_are_nonnegative(self):
        """IOA values must be non-negative integers."""
        listener, devices, result = _run_listener_test(
            "iec104",
            "IEC104PassiveListener",
            "iec60870_104",
            "iec104/emreekin_iec104_baselines.pcap",
            expect_details=["type_id"],
        )

        for ix in listener.interactions:
            ioa = ix.details.get("ioa")
            if ioa is not None:
                if isinstance(ioa, list):
                    for a in ioa:
                        assert isinstance(a, int) and a >= 0, (
                            f"IOA should be non-negative int, got {a}"
                        )
                else:
                    assert isinstance(ioa, int) and ioa >= 0, (
                        f"IOA should be non-negative int, got {ioa}"
                    )

    def test_session_ioa_seen_nonempty(self):
        """Sessions must have non-empty ioa_seen sets."""
        listener, devices, result = _run_listener_test(
            "iec104",
            "IEC104PassiveListener",
            "iec60870_104",
            "iec104/emreekin_iec104_baselines.pcap",
            expect_details=["type_id"],
        )

        for key, session in listener.sessions.items():
            assert len(session.ioa_seen) > 0, f"Session {key} has empty ioa_seen"

    def test_known_ioa_values(self):
        """Baselines pcap has IOAs 0, 1, 2, 3, 12, 13, 14."""
        listener, devices, result = _run_listener_test(
            "iec104",
            "IEC104PassiveListener",
            "iec60870_104",
            "iec104/emreekin_iec104_baselines.pcap",
            expect_details=["type_id"],
        )

        all_ioas = set()
        for session in listener.sessions.values():
            all_ioas.update(session.ioa_seen)

        # Known IOAs from the baselines pcap
        expected_ioas = {0, 1, 2, 3}
        found = expected_ioas & all_ioas
        assert len(found) >= 2, (
            f"Expected at least 2 of {expected_ioas} in IOAs; found {found} in {all_ioas}"
        )


# ========================================================================
# Read/Write Classification Tests
# ========================================================================


class TestIEC104RW:
    """Test read/write classification of interactions."""

    def test_interactions_have_rw(self):
        """I-frame interactions must have 'rw' set to 'read' or 'write'."""
        listener, devices, result = _run_listener_test(
            "iec104",
            "IEC104PassiveListener",
            "iec60870_104",
            "iec104/emreekin_iec104_baselines.pcap",
            expect_details=["rw"],
        )

        i_frame_interactions = [
            ix for ix in listener.interactions if ix.details.get("type_id") is not None
        ]
        assert len(i_frame_interactions) > 0, "No I-frame interactions found"

        for ix in i_frame_interactions:
            rw = ix.details.get("rw")
            assert rw in ("read", "write"), f"rw should be 'read' or 'write', got {rw!r}"

    def test_control_types_are_write(self):
        """Control type IDs (45-64, 100-103) get a control-direction classification.

        The listener picks the most specific label per type+COT:
        - Pure write commands (single/double/setpoint): rw='write'
        - Read-via-control (e.g. type 100 Interrogation): rw='read'
        - Error confirmations (negative COT on a control): rw='error'
        - System commands (clock sync, test): rw='control'
        - File transfer commands: rw='file'

        It must never silently fall through to a default — every control
        type produces one of these distinct labels, never empty or None.
        """
        listener, devices, result = _run_listener_test(
            "iec104",
            "IEC104PassiveListener",
            "iec60870_104",
            "iec104/emreekin_iec104_baselines.pcap",
            expect_details=["type_id"],
        )

        from oida.pcap.iec104 import CONTROL_TYPE_IDS

        allowed = {"write", "read", "error", "control", "file"}
        for ix in listener.interactions:
            type_id = ix.details.get("type_id")
            if type_id is not None and type_id in CONTROL_TYPE_IDS:
                assert ix.details.get("rw") in allowed, (
                    f"Control type {type_id} got unexpected rw={ix.details.get('rw')!r}"
                )

    def test_monitoring_types_are_read(self):
        """Monitoring type IDs (1-40) must be classified as 'read'."""
        listener, devices, result = _run_listener_test(
            "iec104",
            "IEC104PassiveListener",
            "iec60870_104",
            "iec104/emreekin_iec104_type58_59.pcap",
            expect_details=["type_id"],
        )

        from oida.pcap.iec104 import CONTROL_TYPE_IDS

        for ix in listener.interactions:
            type_id = ix.details.get("type_id")
            if type_id is not None and type_id not in CONTROL_TYPE_IDS:
                assert ix.details.get("rw") == "read", (
                    f"Monitoring type {type_id} should be 'read', got {ix.details.get('rw')}"
                )

    def test_baselines_has_both_read_and_write(self):
        """Baselines pcap must contain both read (monitoring) and write (control)."""
        listener, devices, result = _run_listener_test(
            "iec104",
            "IEC104PassiveListener",
            "iec60870_104",
            "iec104/emreekin_iec104_baselines.pcap",
            expect_details=["rw"],
        )

        rw_values = set()
        for ix in listener.interactions:
            rw = ix.details.get("rw")
            if rw:
                rw_values.add(rw)

        assert "write" in rw_values, "No 'write' interactions found in baselines pcap"
        assert "read" in rw_values, "No 'read' interactions found in baselines pcap"


# ========================================================================
# Session-Level Data Tests
# ========================================================================


class TestIEC104SessionFields:
    """Test session-level data fields."""

    def test_baselines_monitor_count(self):
        """Baselines pcap sessions must have monitor_count >= 1."""
        listener, devices, result = _run_listener_test(
            "iec104",
            "IEC104PassiveListener",
            "iec60870_104",
            "iec104/emreekin_iec104_baselines.pcap",
            expect_details=["type_id"],
        )

        total_monitor = sum(s.monitor_count for s in listener.sessions.values())
        assert total_monitor >= 1, f"Expected total monitor_count >= 1, got {total_monitor}"

    def test_baselines_control_count(self):
        """Baselines pcap sessions must have control_count > 0 (many commands)."""
        listener, devices, result = _run_listener_test(
            "iec104",
            "IEC104PassiveListener",
            "iec60870_104",
            "iec104/emreekin_iec104_baselines.pcap",
            expect_details=["type_id"],
        )

        total_control = sum(s.control_count for s in listener.sessions.values())
        assert total_control > 0, f"Expected control_count > 0, got {total_control}"

    def test_session_controlling_controlled_ips(self):
        """Sessions must have valid controlling and controlled IP addresses."""
        listener, devices, result = _run_listener_test(
            "iec104",
            "IEC104PassiveListener",
            "iec60870_104",
            "iec104/emreekin_iec104_baselines.pcap",
            expect_details=["type_id"],
        )

        for session in listener.sessions.values():
            assert session.controlling_ip, "Session has no controlling_ip"
            assert session.controlled_ip, "Session has no controlled_ip"
            # IPs should look like IP addresses
            assert "." in session.controlling_ip, (
                f"controlling_ip doesn't look like IPv4: {session.controlling_ip}"
            )
            assert "." in session.controlled_ip, (
                f"controlled_ip doesn't look like IPv4: {session.controlled_ip}"
            )

    def test_session_timestamps(self):
        """Sessions must have first_seen and last_seen timestamps."""
        listener, devices, result = _run_listener_test(
            "iec104",
            "IEC104PassiveListener",
            "iec60870_104",
            "iec104/emreekin_iec104_baselines.pcap",
            expect_details=["type_id"],
        )

        for session in listener.sessions.values():
            assert session.first_seen, "Session has no first_seen"
            assert session.last_seen, "Session has no last_seen"

    def test_sessions_summary(self):
        """get_sessions_summary() must return structured session data."""
        listener, devices, result = _run_listener_test(
            "iec104",
            "IEC104PassiveListener",
            "iec60870_104",
            "iec104/emreekin_iec104_baselines.pcap",
            expect_details=["type_id"],
        )

        summary = listener.get_sessions_summary()
        assert isinstance(summary, list), f"Sessions summary should be a list, got {type(summary)}"
        assert len(summary) >= 1, "Expected at least 1 session summary"

        for entry in summary:
            assert "controlling" in entry
            assert "controlled" in entry
            assert "common_addresses" in entry
            assert "type_ids" in entry
            assert "control_count" in entry
            assert "monitor_count" in entry
            # common_addresses should be a sorted list
            assert isinstance(entry["common_addresses"], list)


# ========================================================================
# Device Passive Data Tests
# ========================================================================


class TestIEC104DeviceData:
    """Test iec104_passive_data completeness on devices."""

    def test_passive_data_has_all_expected_keys(self):
        """iec104_passive_data must contain all expected keys."""
        listener, devices, result = _run_listener_test(
            "iec104",
            "IEC104PassiveListener",
            "iec60870_104",
            "iec104/emreekin_iec104_baselines.pcap",
            expect_details=["type_id"],
        )

        expected_keys = {
            "role",
            "common_addresses",
            "type_ids_seen",
            "type_names",
            "ioa_ranges",
            "control_commands",
            "monitor_messages",
            "protocol",
        }

        for dev in devices.values():
            data = getattr(dev, "iec104_passive_data", None)
            if data:
                missing = expected_keys - set(data.keys())
                assert not missing, (
                    f"iec104_passive_data missing keys: {missing}; has: {set(data.keys())}"
                )

    def test_passive_data_field_types(self):
        """iec104_passive_data fields must have correct types."""
        listener, devices, result = _run_listener_test(
            "iec104",
            "IEC104PassiveListener",
            "iec60870_104",
            "iec104/emreekin_iec104_baselines.pcap",
            expect_details=["type_id"],
        )

        for dev in devices.values():
            data = getattr(dev, "iec104_passive_data", None)
            if not data:
                continue

            assert isinstance(data["role"], str), f"role should be str, got {type(data['role'])}"
            assert data["role"] in ("controlling_station", "controlled_station"), (
                f"role should be controlling/controlled_station, got {data['role']}"
            )
            assert isinstance(data["common_addresses"], list), (
                f"common_addresses should be list, got {type(data['common_addresses'])}"
            )
            assert isinstance(data["type_ids_seen"], list), (
                f"type_ids_seen should be list, got {type(data['type_ids_seen'])}"
            )
            assert isinstance(data["type_names"], list), (
                f"type_names should be list, got {type(data['type_names'])}"
            )
            assert isinstance(data["ioa_ranges"], list), (
                f"ioa_ranges should be list, got {type(data['ioa_ranges'])}"
            )
            assert isinstance(data["control_commands"], int), (
                f"control_commands should be int, got {type(data['control_commands'])}"
            )
            assert isinstance(data["monitor_messages"], int), (
                f"monitor_messages should be int, got {type(data['monitor_messages'])}"
            )
            assert data["protocol"] == "IEC104/TCP", (
                f"protocol should be 'IEC104/TCP', got {data['protocol']}"
            )

    def test_baselines_passive_data_values(self):
        """Baselines pcap passive data has known values (CA=10, many type IDs)."""
        listener, devices, result = _run_listener_test(
            "iec104",
            "IEC104PassiveListener",
            "iec60870_104",
            "iec104/emreekin_iec104_baselines.pcap",
            expect_details=["type_id"],
        )

        # Find any device with passive data
        all_data = [getattr(d, "iec104_passive_data", None) for d in devices.values()]
        data_list = [d for d in all_data if d]
        assert len(data_list) > 0, "No devices with iec104_passive_data"

        # Check known values from baselines pcap
        for data in data_list:
            assert 10 in data["common_addresses"], (
                f"Expected CA 10 in common_addresses; got {data['common_addresses']}"
            )
            assert len(data["type_ids_seen"]) >= 5, (
                f"Expected >= 5 type IDs; got {len(data['type_ids_seen'])}"
            )
            assert len(data["type_names"]) == len(data["type_ids_seen"]), (
                "type_names and type_ids_seen should have same length"
            )

    def test_device_roles_assigned(self):
        """Both controlling and controlled station roles must be assigned."""
        listener, devices, result = _run_listener_test(
            "iec104",
            "IEC104PassiveListener",
            "iec60870_104",
            "iec104/emreekin_iec104_baselines.pcap",
            expect_details=["type_id"],
        )

        roles = set()
        for dev in devices.values():
            data = getattr(dev, "iec104_passive_data", None)
            if data:
                roles.add(data.get("role"))

        assert "controlling_station" in roles, "No device has role='controlling_station'"
        assert "controlled_station" in roles, "No device has role='controlled_station'"

    def test_ioa_ranges_format(self):
        """IOA ranges should be tuples/lists of (start, end) pairs."""
        listener, devices, result = _run_listener_test(
            "iec104",
            "IEC104PassiveListener",
            "iec60870_104",
            "iec104/emreekin_iec104_baselines.pcap",
            expect_details=["type_id"],
        )

        for dev in devices.values():
            data = getattr(dev, "iec104_passive_data", None)
            if data and data.get("ioa_ranges"):
                for rng in data["ioa_ranges"]:
                    assert len(rng) == 2, (
                        f"IOA range should have 2 elements (start, end), got {rng}"
                    )
                    assert rng[0] <= rng[1], f"IOA range start should be <= end: {rng}"


# ========================================================================
# Protocol Columns / Formatting Tests
# ========================================================================


class TestIEC104ProtocolColumns:
    """Test _format_protocol_columns() output."""

    def test_columns_match_protocol_columns_count(self):
        """_format_protocol_columns output must match PROTOCOL_COLUMNS length."""
        listener, devices, result = _run_listener_test(
            "iec104",
            "IEC104PassiveListener",
            "iec60870_104",
            "iec104/emreekin_iec104_baselines.pcap",
            expect_details=["type_id"],
        )

        from oida.pcap.iec104 import IEC104PassiveListener

        expected_cols = len(IEC104PassiveListener.PROTOCOL_COLUMNS)

        for ix in listener.interactions:
            row = listener._format_protocol_columns(ix)
            assert len(row) == expected_cols, (
                f"Row has {len(row)} columns but PROTOCOL_COLUMNS has {expected_cols}: {row}"
            )

    def test_i_frame_columns_have_content(self):
        """I-frame interactions should have non-empty columns (not all blank)."""
        listener, devices, result = _run_listener_test(
            "iec104",
            "IEC104PassiveListener",
            "iec60870_104",
            "iec104/emreekin_iec104_baselines.pcap",
            expect_details=["type_id"],
        )

        i_frame_count = 0
        nonempty_count = 0
        for ix in listener.interactions:
            if ix.details.get("type_id") is not None:
                i_frame_count += 1
                row = listener._format_protocol_columns(ix)
                if any(c for c in row if c not in (None, "", 0)):
                    nonempty_count += 1

        assert i_frame_count > 0, "No I-frame interactions to check"
        assert nonempty_count == i_frame_count, (
            f"Expected all I-frame rows to have non-empty columns; "
            f"{nonempty_count}/{i_frame_count} had content"
        )

    def test_protocol_columns_tuple_contents(self):
        """PROTOCOL_COLUMNS must contain expected column names."""
        from oida.pcap.iec104 import IEC104PassiveListener

        expected = {"rw", "operation", "type_id", "common_addr", "ioa", "value", "quality", "cot"}
        actual = set(IEC104PassiveListener.PROTOCOL_COLUMNS)
        assert actual == expected, f"PROTOCOL_COLUMNS mismatch; expected {expected}, got {actual}"


# ========================================================================
# Control Command Detection Tests (type58_59 pcap)
# ========================================================================


class TestIEC104ControlDetection:
    """Test control command detection using type58_59 pcap."""

    def test_control_count_positive(self):
        """Type58_59 pcap must have control_count > 0."""
        listener, devices, result = _run_listener_test(
            "iec104",
            "IEC104PassiveListener",
            "iec60870_104",
            "iec104/emreekin_iec104_type58_59.pcap",
            expect_details=["type_id"],
        )

        total_control = sum(s.control_count for s in listener.sessions.values())
        assert total_control > 0, f"Expected control_count > 0, got {total_control}"

    def test_get_control_operations_nonempty(self):
        """get_control_operations() must return non-empty result."""
        listener, devices, result = _run_listener_test(
            "iec104",
            "IEC104PassiveListener",
            "iec60870_104",
            "iec104/emreekin_iec104_type58_59.pcap",
            expect_details=["type_id"],
        )

        ctrl = listener.get_control_operations()
        assert len(ctrl) > 0, "get_control_operations() returned empty list"

        for entry in ctrl:
            assert "controlling" in entry
            assert "controlled" in entry
            assert "control_count" in entry
            assert entry["control_count"] > 0
            assert "control_types" in entry
            assert len(entry["control_types"]) > 0

    def test_control_interactions_are_write(self):
        """All control command interactions get a control-direction rw label.

        See test_control_types_are_write for the rationale on read/error/
        control/file alongside write. The point is that no control type
        falls through to None or a monitoring-default value.
        """
        listener, devices, result = _run_listener_test(
            "iec104",
            "IEC104PassiveListener",
            "iec60870_104",
            "iec104/emreekin_iec104_type58_59.pcap",
            expect_details=["type_id"],
        )

        from oida.pcap.iec104 import CONTROL_TYPE_IDS

        control_interactions = [
            ix for ix in listener.interactions if ix.details.get("type_id") in CONTROL_TYPE_IDS
        ]
        assert len(control_interactions) > 0, "No control interactions found"

        allowed = {"write", "read", "error", "control", "file"}
        for ix in control_interactions:
            assert ix.details.get("rw") in allowed, (
                f"Control type {ix.details.get('type_id')} got unexpected rw="
                f"{ix.details.get('rw')!r}"
            )

    def test_control_type_names_present(self):
        """Control operations must have recognizable type names."""
        listener, devices, result = _run_listener_test(
            "iec104",
            "IEC104PassiveListener",
            "iec60870_104",
            "iec104/emreekin_iec104_type58_59.pcap",
            expect_details=["type_id"],
        )

        ctrl = listener.get_control_operations()
        all_types = []
        for entry in ctrl:
            all_types.extend(entry["control_types"])

        # Type58_59 pcap has C_SC_NA_1 (45), C_SC_TA_1 (58), C_DC_TA_1 (59)
        all_types_str = " ".join(all_types)
        assert "C_SC" in all_types_str or "C_DC" in all_types_str, (
            f"Expected C_SC or C_DC in control types; got: {all_types}"
        )

    def test_control_common_address(self):
        """Type58_59 pcap uses common address 1."""
        listener, devices, result = _run_listener_test(
            "iec104",
            "IEC104PassiveListener",
            "iec60870_104",
            "iec104/emreekin_iec104_type58_59.pcap",
            expect_details=["type_id"],
        )

        for session in listener.sessions.values():
            assert 1 in session.common_addresses, (
                f"Expected common address 1; got {session.common_addresses}"
            )


# ========================================================================
# U-Frame Tests
# ========================================================================


class TestIEC104UFrame:
    """Test U-frame handling (STARTDT, STOPDT, TESTFR)."""

    def test_u_frame_interactions_recorded(self):
        """U-frame interactions (STARTDT, TESTFR, etc.) must be recorded."""
        listener, devices, result = _run_listener_test(
            "iec104",
            "IEC104PassiveListener",
            "iec60870_104",
            "iec104/emreekin_iec104_baselines.pcap",
            expect_details=["type_id"],
        )

        u_frame_interactions = [ix for ix in listener.interactions if "utype" in ix.details]
        assert len(u_frame_interactions) > 0, "No U-frame interactions recorded"

    def test_u_frame_has_utype_field(self):
        """U-frame interactions must have 'utype' in details."""
        listener, devices, result = _run_listener_test(
            "iec104",
            "IEC104PassiveListener",
            "iec60870_104",
            "iec104/emreekin_iec104_baselines.pcap",
            expect_details=["type_id"],
        )

        for ix in listener.interactions:
            if "utype" in ix.details:
                assert isinstance(ix.details["utype"], int), (
                    f"utype should be int, got {type(ix.details['utype'])}"
                )

    def test_industroyer_startdt(self):
        """Industroyer2 pcap must have STARTDT frames detected."""
        listener, devices, result = _run_listener_test(
            "iec104",
            "IEC104PassiveListener",
            "iec60870_104",
            "iec104/eset_industroyer2_sample1.pcap",
            expect_details=["type_id"],
        )

        # Industroyer2 sends STARTDT act before commands
        startdt_found = any(s.startdt_seen for s in listener.sessions.values())
        assert startdt_found, "Expected STARTDT to be seen in Industroyer2 pcap"


# ========================================================================
# Industroyer2 Malware Traffic Tests
# ========================================================================


class TestIEC104Industroyer:
    """Test against real Industroyer2 malware IEC 104 attack traffic."""

    def test_industroyer2_produces_interactions(self):
        """Industroyer2 sample must produce interactions without crashing."""
        listener, devices, result = _run_listener_test(
            "iec104",
            "IEC104PassiveListener",
            "iec60870_104",
            "iec104/eset_industroyer2_sample1.pcap",
            expect_details=["type_id"],
            min_interactions=10,
        )

        assert len(listener.interactions) >= 10, (
            f"Expected >= 10 interactions from Industroyer2; got {len(listener.interactions)}"
        )

    def test_industroyer2_multiple_sessions(self):
        """Industroyer2 targets multiple controlled stations (3 RTUs)."""
        listener, devices, result = _run_listener_test(
            "iec104",
            "IEC104PassiveListener",
            "iec60870_104",
            "iec104/eset_industroyer2_sample1.pcap",
            expect_details=["type_id"],
        )

        assert len(listener.sessions) >= 3, (
            f"Expected >= 3 sessions (3 target RTUs); got {len(listener.sessions)}"
        )

    def test_industroyer2_all_control_commands(self):
        """Industroyer2 sends only control commands (no monitoring responses)."""
        listener, devices, result = _run_listener_test(
            "iec104",
            "IEC104PassiveListener",
            "iec60870_104",
            "iec104/eset_industroyer2_sample1.pcap",
            expect_details=["type_id"],
        )

        total_control = sum(s.control_count for s in listener.sessions.values())
        total_monitor = sum(s.monitor_count for s in listener.sessions.values())

        assert total_control > 0, "Expected control commands in Industroyer2"
        assert total_control > total_monitor, (
            f"Industroyer2 should have more control than monitoring; "
            f"control={total_control}, monitor={total_monitor}"
        )

    def test_industroyer2_control_operations(self):
        """Industroyer2 attack must be detected by get_control_operations()."""
        listener, devices, result = _run_listener_test(
            "iec104",
            "IEC104PassiveListener",
            "iec60870_104",
            "iec104/eset_industroyer2_sample1.pcap",
            expect_details=["type_id"],
        )

        ctrl = listener.get_control_operations()
        assert len(ctrl) >= 3, (
            f"Expected >= 3 control operation entries (3 targets); got {len(ctrl)}"
        )

        # Verify attacker IP is consistent (10.9.9.9)
        controlling_ips = {e["controlling"] for e in ctrl}
        assert "10.9.9.9" in controlling_ips, (
            f"Expected attacker IP 10.9.9.9 as controlling; got {controlling_ips}"
        )

    def test_industroyer2_target_ips(self):
        """Industroyer2 targets 10.1.1.1, 10.1.1.2, 10.1.1.3."""
        listener, devices, result = _run_listener_test(
            "iec104",
            "IEC104PassiveListener",
            "iec60870_104",
            "iec104/eset_industroyer2_sample1.pcap",
            expect_details=["type_id"],
        )

        controlled_ips = {s.controlled_ip for s in listener.sessions.values()}
        expected_targets = {"10.1.1.1", "10.1.1.2", "10.1.1.3"}
        found = expected_targets & controlled_ips
        assert len(found) >= 3, f"Expected Industroyer2 targets {expected_targets}; found {found}"

    def test_industroyer2_devices_discovered(self):
        """Industroyer2 must discover attacker and target devices."""
        listener, devices, result = _run_listener_test(
            "iec104",
            "IEC104PassiveListener",
            "iec60870_104",
            "iec104/eset_industroyer2_sample1.pcap",
            min_devices=4,
            expect_details=["type_id"],
        )

        # Should have: 1 attacker (controlling) + 3 targets (controlled) = 4+ devices
        assert len(devices) >= 4, (
            f"Expected >= 4 devices (1 attacker + 3 targets); got {len(devices)}"
        )

    def test_industroyer2_harvest_no_crash(self):
        """Industroyer2 harvest must complete without raw dicts/sets in cells."""
        listener, devices, result = _run_listener_test(
            "iec104",
            "IEC104PassiveListener",
            "iec60870_104",
            "iec104/eset_industroyer2_sample1.pcap",
            expect_details=["type_id"],
            check_harvest=True,
        )

        # harvest() should return dict (may be empty if no custom tables)
        assert isinstance(result, dict)


# ========================================================================
# Diverse Traffic Tests (iti_090813_diverse pcap)
# ========================================================================


class TestIEC104Diverse:
    """Test with diverse IEC 104 traffic (monitoring + control mixed)."""

    def test_diverse_has_monitoring_and_control(self):
        """Diverse pcap must have both monitoring and control types."""
        listener, devices, result = _run_listener_test(
            "iec104",
            "IEC104PassiveListener",
            "iec60870_104",
            "iec104/iti_090813_diverse.pcap",
            expect_details=["type_id"],
        )

        total_monitor = sum(s.monitor_count for s in listener.sessions.values())
        total_control = sum(s.control_count for s in listener.sessions.values())

        assert total_monitor > 0, "Expected monitoring messages in diverse pcap"
        assert total_control > 0, "Expected control commands in diverse pcap"

    def test_diverse_multiple_type_ids(self):
        """Diverse pcap must have multiple distinct type IDs."""
        listener, devices, result = _run_listener_test(
            "iec104",
            "IEC104PassiveListener",
            "iec60870_104",
            "iec104/iti_090813_diverse.pcap",
            expect_details=["type_id"],
        )

        all_type_ids = set()
        for session in listener.sessions.values():
            all_type_ids.update(session.type_ids)

        assert len(all_type_ids) >= 5, (
            f"Expected >= 5 distinct type IDs in diverse pcap; got {len(all_type_ids)}: {all_type_ids}"
        )

    def test_diverse_values_extracted(self):
        """Diverse pcap must have values extracted from monitoring types."""
        listener, devices, result = _run_listener_test(
            "iec104",
            "IEC104PassiveListener",
            "iec60870_104",
            "iec104/iti_090813_diverse.pcap",
            expect_details=["type_id"],
        )

        has_values = sum(1 for ix in listener.interactions if ix.details.get("values"))
        assert has_values > 0, "Expected some interactions with values in diverse pcap"

    def test_diverse_quality_extracted(self):
        """Diverse pcap must have quality extracted from monitoring types."""
        listener, devices, result = _run_listener_test(
            "iec104",
            "IEC104PassiveListener",
            "iec60870_104",
            "iec104/iti_090813_diverse.pcap",
            expect_details=["type_id"],
        )

        has_quality = sum(
            1 for ix in listener.interactions if ix.details.get("quality") is not None
        )
        assert has_quality > 0, "Expected some interactions with quality in diverse pcap"


# ========================================================================
# Cause of Transmission Tests
# ========================================================================


class TestIEC104CauseOfTransmission:
    """Test cause of transmission extraction."""

    def test_cause_of_transmission_is_int(self):
        """cause_of_transmission must be an integer when present."""
        listener, devices, result = _run_listener_test(
            "iec104",
            "IEC104PassiveListener",
            "iec60870_104",
            "iec104/emreekin_iec104_baselines.pcap",
            expect_details=["type_id"],
        )

        for ix in listener.interactions:
            cot = ix.details.get("cause_of_transmission")
            if cot is not None:
                assert isinstance(cot, int), f"cause_of_transmission should be int, got {type(cot)}"
                assert cot >= 0, f"cause_of_transmission should be non-negative, got {cot}"

    def test_baselines_has_activation_cause(self):
        """Baselines pcap has cause=6 (activation) for commands."""
        listener, devices, result = _run_listener_test(
            "iec104",
            "IEC104PassiveListener",
            "iec60870_104",
            "iec104/emreekin_iec104_baselines.pcap",
            expect_details=["type_id"],
        )

        causes = set()
        for ix in listener.interactions:
            cot = ix.details.get("cause_of_transmission")
            if cot is not None:
                causes.add(cot)

        # Cause 6 = activation, which should be in command pcaps
        assert 6 in causes, f"Expected cause_of_transmission=6 (activation); found: {causes}"


# ========================================================================
# Interaction Summary and Operation Tests
# ========================================================================


class TestIEC104Operations:
    """Test interaction operations and summaries."""

    def test_baselines_operations_present(self):
        """Baselines pcap must have known operation types."""
        listener, devices, result = _run_listener_test(
            "iec104",
            "IEC104PassiveListener",
            "iec60870_104",
            "iec104/emreekin_iec104_baselines.pcap",
            expect_details=["type_id"],
        )

        ops = {ix.operation for ix in listener.interactions if ix.operation}
        # Baselines pcap has: C_SC_NA_1, C_DC_NA_1, C_RC_NA_1, C_SE_NA_1,
        # C_SE_NB_1, C_SE_NC_1, C_BO_NA_1, C_IC_NA_1, M_EI_NA_1
        assert "C_SC_NA_1" in ops, f"Expected C_SC_NA_1 in operations; got {ops}"
        assert "C_IC_NA_1" in ops, f"Expected C_IC_NA_1 in operations; got {ops}"

    def test_interaction_summaries_nonempty(self):
        """I-frame interactions should have non-empty summaries."""
        listener, devices, result = _run_listener_test(
            "iec104",
            "IEC104PassiveListener",
            "iec60870_104",
            "iec104/emreekin_iec104_baselines.pcap",
            expect_details=["type_id"],
        )

        i_frame_interactions = [
            ix for ix in listener.interactions if ix.details.get("type_id") is not None
        ]
        assert all(ix.summary for ix in i_frame_interactions), (
            "Expected all I-frame interactions to have non-empty summaries"
        )

    def test_summary_contains_cmd_or_mon_prefix(self):
        """I-frame summaries must start with CMD or MON prefix."""
        listener, devices, result = _run_listener_test(
            "iec104",
            "IEC104PassiveListener",
            "iec60870_104",
            "iec104/emreekin_iec104_baselines.pcap",
            expect_details=["type_id"],
        )

        for ix in listener.interactions:
            if ix.details.get("type_id") is not None:
                assert ix.summary.startswith("CMD ") or ix.summary.startswith("MON "), (
                    f"Summary should start with CMD or MON: {ix.summary!r}"
                )

    def test_interactions_have_direction(self):
        """All interactions must have direction set to 'request' or 'response'."""
        listener, devices, result = _run_listener_test(
            "iec104",
            "IEC104PassiveListener",
            "iec60870_104",
            "iec104/emreekin_iec104_baselines.pcap",
            expect_details=["type_id"],
        )

        for ix in listener.interactions:
            assert ix.direction in ("request", "response"), (
                f"direction should be 'request' or 'response', got {ix.direction!r}"
            )

    def test_interactions_have_ips(self):
        """All interactions must have src_ip and dst_ip set."""
        listener, devices, result = _run_listener_test(
            "iec104",
            "IEC104PassiveListener",
            "iec60870_104",
            "iec104/emreekin_iec104_baselines.pcap",
            expect_details=["type_id"],
        )

        for ix in listener.interactions:
            assert ix.src_ip, f"Interaction has no src_ip: {ix}"
            assert ix.dst_ip, f"Interaction has no dst_ip: {ix}"


# ========================================================================
# Type-Specific Pcap Tests
# ========================================================================


class TestIEC104TypeSpecific:
    """Test type-specific pcap fixtures for targeted coverage."""

    def test_type50_setpoint_float(self):
        """Type50 pcap (C_SE_NC_1 float setpoint) must extract float values."""
        listener, devices, result = _run_listener_test(
            "iec104",
            "IEC104PassiveListener",
            "iec60870_104",
            "iec104/emreekin_iec104_type50.pcap",
            expect_details=["type_id"],
        )

        # All interactions should be C_SE_NC_1 (type 50)
        for ix in listener.interactions:
            if ix.details.get("type_id") is not None:
                assert ix.details["type_id"] == 50, (
                    f"Expected type_id 50, got {ix.details['type_id']}"
                )
                assert ix.details.get("type_name") == "C_SE_NC_1"
                assert ix.details.get("rw") == "write"
                assert ix.details.get("values"), f"C_SE_NC_1 should have values: {ix.details}"

    def test_type58_59_time_tagged_commands(self):
        """Type58/59 pcap must have time-tagged single/double commands."""
        listener, devices, result = _run_listener_test(
            "iec104",
            "IEC104PassiveListener",
            "iec60870_104",
            "iec104/emreekin_iec104_type58_59.pcap",
            expect_details=["type_id"],
        )

        type_ids = set()
        for ix in listener.interactions:
            tid = ix.details.get("type_id")
            if tid is not None:
                type_ids.add(tid)

        # Should have C_SC_TA_1 (58) and C_DC_TA_1 (59)
        assert 58 in type_ids or 59 in type_ids, (
            f"Expected type 58 or 59 in type58_59 pcap; got {type_ids}"
        )

    def test_type58_59_monitoring_types(self):
        """Type58_59 pcap also has monitoring types M_SP_TB_1 (30) and M_DP_TB_1 (31)."""
        listener, devices, result = _run_listener_test(
            "iec104",
            "IEC104PassiveListener",
            "iec60870_104",
            "iec104/emreekin_iec104_type58_59.pcap",
            expect_details=["type_id"],
        )

        type_ids = set()
        for ix in listener.interactions:
            tid = ix.details.get("type_id")
            if tid is not None:
                type_ids.add(tid)

        assert 30 in type_ids or 31 in type_ids, (
            f"Expected monitoring type 30 or 31 in type58_59 pcap; got {type_ids}"
        )


# ========================================================================
# Harvest and Alerts Tests
# ========================================================================


class TestIEC104Harvest:
    """Test harvest() output including control alerts."""

    def test_harvest_returns_dict(self):
        """harvest() must return a dict."""
        listener, devices, result = _run_listener_test(
            "iec104",
            "IEC104PassiveListener",
            "iec60870_104",
            "iec104/emreekin_iec104_baselines.pcap",
            expect_details=["type_id"],
            check_harvest=True,
        )

        assert isinstance(result, dict)

    def test_harvest_control_alerts(self):
        """Pcaps with control commands should produce control alerts in harvest."""
        listener, devices, result = _run_listener_test(
            "iec104",
            "IEC104PassiveListener",
            "iec60870_104",
            "iec104/emreekin_iec104_baselines.pcap",
            expect_details=["type_id"],
            check_harvest=True,
        )

        # baselines pcap has control commands, so harvest should have alerts
        alerts = result.get("alerts", [])
        control_alerts = [a for a in alerts if "CONTROL" in a.get("message", "")]
        assert len(control_alerts) > 0, (
            f"Expected control alerts in harvest for pcap with commands; alerts: {alerts}"
        )

    def test_harvest_alert_structure(self):
        """Harvest alerts must have required fields."""
        listener, devices, result = _run_listener_test(
            "iec104",
            "IEC104PassiveListener",
            "iec60870_104",
            "iec104/emreekin_iec104_baselines.pcap",
            expect_details=["type_id"],
            check_harvest=True,
        )

        for alert in result.get("alerts", []):
            assert "level" in alert, f"Alert missing 'level': {alert}"
            assert "message" in alert, f"Alert missing 'message': {alert}"
            assert alert["level"] in ("fail", "warning", "info"), (
                f"Unexpected alert level: {alert['level']}"
            )


# ========================================================================
# NDPI Pcap Tests (monitoring only, small)
# ========================================================================


class TestIEC104NDPI:
    """Test with NDPI pcap (monitoring-only traffic with M_ME_TF_1)."""

    def test_ndpi_monitoring_only(self):
        """NDPI pcap has only monitoring traffic (no control commands)."""
        listener, devices, result = _run_listener_test(
            "iec104",
            "IEC104PassiveListener",
            "iec60870_104",
            "iec104/ndpi_iec104.pcap",
            expect_details=["type_id"],
        )

        for session in listener.sessions.values():
            if session.type_ids:
                assert session.monitor_count > 0, (
                    "NDPI session with type_ids should have monitor_count > 0"
                )

    def test_ndpi_float_measurement_type(self):
        """NDPI pcap has M_ME_TF_1 (type 36) - float measurement with time."""
        listener, devices, result = _run_listener_test(
            "iec104",
            "IEC104PassiveListener",
            "iec60870_104",
            "iec104/ndpi_iec104.pcap",
            expect_details=["type_id"],
        )

        ops = {ix.operation for ix in listener.interactions}
        assert "M_ME_TF_1" in ops, f"Expected M_ME_TF_1 operation in NDPI pcap; got {ops}"
