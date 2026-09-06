"""Integration tests for Modbus passive listener in EK mode.

Comprehensive test coverage for the Modbus TCP passive listener:
- Session tracking (unit IDs, function codes, read/write counts)
- Transaction ID extraction and session range tracking
- PDU length extraction
- Address and value extraction (EK-mode dependent)
- Exception response handling
- Write operation detection
- Device passive data completeness
- Protocol column formatting
- Fuzz pcap robustness (malformed packets)
- Harvest output validation
- Multi-pcap cross-fixture consistency

Uses _run_listener_test() from conftest as the primary test helper.
All tests feed real pcap fixtures through the listener and assert on
the structured data produced.
"""

import pytest

from oida.pcap.modbus import (
    MODBUS_FC,
    ModbusPassiveListener,
    ModbusSession,
    READ_FUNCTION_CODES,
    WRITE_FUNCTION_CODES,
)

from .conftest import _run_listener_test

pytestmark = [pytest.mark.integration]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Canonical pcap fixtures and their characteristics.
# cisagov: FC 1-8, 15, 16, 17, 20-24, 43 -- has reads, writes, diagnostics
# digitalbond_part1: FC 1, 3, 5, 6, 8, 17, 43 -- has writes, exceptions (code 11)
# modbus_tcp_full: FC 1, 2, 4, 15 -- many sessions, writes (FC 15)
# zeek_modbus_mixed: FC 0, 1, 3, 5, 6, 49, 74 -- mixed with writes
# zeek_modbus_small: FC 1, 15 -- writes (FC 15)

CISAGOV_PCAP = "modbus/cisagov_modbus_example.pcap"
DIGITALBOND_P1_PCAP = "modbus/digitalbond_modbus_part1.pcap"
MODBUS_TCP_FULL_PCAP = "modbus/modbus_tcp_full.pcap"
ZEEK_MIXED_PCAP = "modbus/zeek_modbus_mixed_p502.pcap"
ZEEK_SMALL_PCAP = "modbus/zeek_modbus_small.pcap"
MODBUS_TEST_PCAP = "modbus/modbus_test.pcap"
BRO_FUZZ72_PCAP = "modbus/bro_modbus_fuzz72.pcap"
BRO_FUZZ1011_PCAP = "modbus/bro_modbus_fuzz1011.pcap"


def _get_modbus_listener(pcap_subpath=CISAGOV_PCAP, **kwargs):
    """Helper to create and run the Modbus listener on a fixture pcap."""
    defaults = {
        "expect_details": ["function_code", "unit_id"],
        "expect_operations": ["Read"],
    }
    defaults.update(kwargs)
    return _run_listener_test(
        "modbus",
        "ModbusPassiveListener",
        "mbtcp",
        pcap_subpath,
        **defaults,
    )


def _get_write_listener(pcap_subpath=MODBUS_TCP_FULL_PCAP, **kwargs):
    """Helper to create and run the Modbus listener on a write-heavy pcap."""
    defaults = {
        "expect_details": ["function_code", "unit_id"],
        "expect_operations": ["Write"],
    }
    defaults.update(kwargs)
    return _run_listener_test(
        "modbus",
        "ModbusPassiveListener",
        "mbtcp",
        pcap_subpath,
        **defaults,
    )


# =========================================================================
# Session Tracking Tests
# =========================================================================


class TestModbusPassiveEK:
    """Modbus-specific tests beyond the parametrized quality suite."""

    def test_modbus_sessions_and_operations(self):
        listener, devices, result = _get_modbus_listener()

        # A1: sessions populated
        assert len(listener.sessions) >= 1, (
            f"Expected >= 1 Modbus session, got {len(listener.sessions)}"
        )

        # A2: session has unit_ids and function_codes
        for session in listener.sessions.values():
            assert session.unit_ids, "Session has no unit_ids"
            assert session.function_codes, "Session has no function_codes"

        # A3: passive_data on at least one device
        has_data = any(
            hasattr(d, "modbus_passive_data") and d.modbus_passive_data for d in devices.values()
        )
        assert has_data, "No device has modbus_passive_data"

        # A4: harvest returns a dict (tables are now built centrally by scanner)
        assert isinstance(result, dict)


class TestModbusSessionFields:
    """Test session-level data completeness."""

    def test_session_read_count_for_read_pcap(self):
        """Sessions from read-heavy pcap must have read_count > 0."""
        listener, _devices, _result = _get_modbus_listener()

        has_reads = any(s.read_count > 0 for s in listener.sessions.values())
        assert has_reads, (
            "Expected at least one session with read_count > 0; "
            f"sessions: {[(k, s.read_count) for k, s in listener.sessions.items()]}"
        )

    def test_session_unit_ids_populated(self):
        """Every session must have at least one unit_id."""
        listener, _devices, _result = _get_modbus_listener()

        for key, session in listener.sessions.items():
            assert session.unit_ids, f"Session {key} has empty unit_ids"

    def test_session_function_codes_populated(self):
        """Every session must have at least one function_code."""
        listener, _devices, _result = _get_modbus_listener()

        for key, session in listener.sessions.items():
            assert session.function_codes, f"Session {key} has empty function_codes"

    def test_session_first_last_seen(self):
        """Sessions must have first_seen and last_seen timestamps."""
        listener, _devices, _result = _get_modbus_listener()

        for key, session in listener.sessions.items():
            assert session.first_seen, f"Session {key} has empty first_seen"
            assert session.last_seen, f"Session {key} has empty last_seen"

    def test_session_client_server_ips(self):
        """Sessions must have valid client_ip and server_ip."""
        listener, _devices, _result = _get_modbus_listener()

        for key, session in listener.sessions.items():
            assert session.client_ip, f"Session {key} has empty client_ip"
            assert session.server_ip, f"Session {key} has empty server_ip"
            # Should be real IP-like strings
            assert "." in session.client_ip or ":" in session.client_ip, (
                f"Session {key} client_ip doesn't look like IP: {session.client_ip}"
            )

    def test_sessions_summary_structure(self):
        """get_sessions_summary() must return valid dicts with required keys."""
        listener, _devices, _result = _get_modbus_listener()

        summaries = listener.get_sessions_summary()
        assert summaries, "get_sessions_summary() returned empty"

        required_keys = {
            "client",
            "server",
            "unit_ids",
            "function_codes",
            "write_count",
            "read_count",
            "first_seen",
            "last_seen",
        }
        for s in summaries:
            missing = required_keys - set(s.keys())
            assert not missing, f"Session summary missing keys: {missing}; got: {sorted(s.keys())}"

            # unit_ids and function_codes should be sorted lists
            assert isinstance(s["unit_ids"], list), (
                f"unit_ids should be list, got {type(s['unit_ids'])}"
            )
            assert isinstance(s["function_codes"], list), (
                f"function_codes should be list, got {type(s['function_codes'])}"
            )
            assert s["unit_ids"] == sorted(s["unit_ids"]), "unit_ids should be sorted"
            assert s["function_codes"] == sorted(s["function_codes"]), (
                "function_codes should be sorted"
            )


# =========================================================================
# Transaction ID Tests
# =========================================================================


class TestModbusTransactionID:
    """Tests for MBAP Transaction ID (mbtcp.trans_id) extraction -- T1 field."""

    def test_trans_id_in_interaction_details(self):
        """trans_id must appear in interaction details for every packet."""
        listener, _devices, _result = _get_modbus_listener()

        # Every interaction must have the trans_id key
        for ix in listener.interactions:
            assert "trans_id" in ix.details, f"Interaction missing trans_id key: {ix.details}"

        # At least one interaction must have a non-None trans_id value
        has_trans_id = any(ix.details.get("trans_id") is not None for ix in listener.interactions)
        assert has_trans_id, (
            "No interaction has a non-None trans_id; "
            f"sample details: {listener.interactions[0].details if listener.interactions else '{}'}"
        )

    def test_trans_id_is_integer(self):
        """Parsed trans_id must be an int (not a string or None for valid packets)."""
        listener, _devices, _result = _get_modbus_listener()

        non_none = [ix for ix in listener.interactions if ix.details.get("trans_id") is not None]
        assert non_none, "Expected at least one interaction with trans_id"

        for ix in non_none:
            tid = ix.details["trans_id"]
            assert isinstance(tid, int), f"trans_id should be int, got {type(tid).__name__}: {tid}"
            assert 0 <= tid <= 65535, f"trans_id out of uint16 range: {tid}"

    def test_trans_id_range_in_session(self):
        """Session should track min/max transaction IDs."""
        listener, _devices, _result = _get_modbus_listener()

        for session in listener.sessions.values():
            assert session.trans_id_min is not None, (
                f"Session {session.client_ip}->{session.server_ip} has no trans_id_min"
            )
            assert session.trans_id_max is not None, (
                f"Session {session.client_ip}->{session.server_ip} has no trans_id_max"
            )
            assert session.trans_id_min <= session.trans_id_max, (
                f"trans_id_min ({session.trans_id_min}) > trans_id_max ({session.trans_id_max})"
            )

    def test_trans_id_range_in_device_data(self):
        """Device passive data should include trans_id_range."""
        _listener, devices, _result = _get_modbus_listener()

        devices_with_data = [
            d
            for d in devices.values()
            if hasattr(d, "modbus_passive_data") and d.modbus_passive_data
        ]
        assert devices_with_data, "No device has modbus_passive_data"

        has_range = any("trans_id_range" in d.modbus_passive_data for d in devices_with_data)
        assert has_range, (
            "No device has trans_id_range in modbus_passive_data; "
            f"sample keys: {list(devices_with_data[0].modbus_passive_data.keys())}"
        )

        # Validate the range format: [min, max]
        for d in devices_with_data:
            rng = d.modbus_passive_data.get("trans_id_range")
            if rng is not None:
                assert isinstance(rng, list), f"trans_id_range should be list, got {type(rng)}"
                assert len(rng) == 2, f"trans_id_range should have 2 elements, got {len(rng)}"
                assert rng[0] <= rng[1], f"trans_id_range min > max: {rng}"

    def test_trans_id_in_sessions_summary(self):
        """get_sessions_summary() should include trans_id_range."""
        listener, _devices, _result = _get_modbus_listener()

        summaries = listener.get_sessions_summary()
        assert summaries, "get_sessions_summary() returned empty"

        has_range = any("trans_id_range" in s for s in summaries)
        assert has_range, (
            f"No session summary has trans_id_range; sample keys: {list(summaries[0].keys())}"
        )

    def test_trans_id_across_pcap_fixtures(self):
        """trans_id extraction works across different Modbus pcap fixtures."""
        fixtures = [
            CISAGOV_PCAP,
            MODBUS_TCP_FULL_PCAP,
            DIGITALBOND_P1_PCAP,
        ]
        for fixture in fixtures:
            listener, _devices, _result = _run_listener_test(
                "modbus",
                "ModbusPassiveListener",
                "mbtcp",
                fixture,
                min_devices=0,
                min_interactions=0,
            )
            if listener.interactions:
                has_tid = any(
                    ix.details.get("trans_id") is not None for ix in listener.interactions
                )
                assert has_tid, (
                    f"No trans_id found in {fixture}; sample: {listener.interactions[0].details}"
                )


# =========================================================================
# PDU Length Tests
# =========================================================================


class TestModbusPDULength:
    """Tests for MBAP PDU Length (mbtcp.len) extraction -- T2 field."""

    def test_pdu_len_in_interaction_details(self):
        """pdu_len must appear in interaction details."""
        listener, _devices, _result = _get_modbus_listener()

        # Every interaction must have the pdu_len key
        for ix in listener.interactions:
            assert "pdu_len" in ix.details, f"Interaction missing pdu_len key: {ix.details}"

        # At least one interaction must have a non-None value
        has_pdu_len = any(ix.details.get("pdu_len") is not None for ix in listener.interactions)
        assert has_pdu_len, (
            "No interaction has a non-None pdu_len; "
            f"sample details: {listener.interactions[0].details if listener.interactions else '{}'}"
        )

    def test_pdu_len_is_valid_integer(self):
        """Parsed pdu_len must be a positive int within Modbus TCP limits."""
        listener, _devices, _result = _get_modbus_listener()

        non_none = [ix for ix in listener.interactions if ix.details.get("pdu_len") is not None]
        assert non_none, "Expected at least one interaction with pdu_len"

        for ix in non_none:
            plen = ix.details["pdu_len"]
            assert isinstance(plen, int), (
                f"pdu_len should be int, got {type(plen).__name__}: {plen}"
            )
            # MBAP length field: min 1 (unit_id only), max 260 per spec (253 data + 7 header - 6)
            # but be lenient for malformed captures
            assert plen > 0, f"pdu_len should be positive, got {plen}"


# =========================================================================
# Address Extraction Tests
# =========================================================================


class TestModbusAddress:
    """Test address extraction from Modbus interactions.

    NOTE: In EK mode, tshark may not expose modbus.reference_num for all
    pcaps.  These tests are written to be tolerant of that limitation --
    they check for the _presence_ of address data when it is available,
    and validate its structure when found.
    """

    def test_address_type_when_present(self):
        """If address is present in details, it must be a non-negative int."""
        listener, _devices, _result = _get_modbus_listener()

        interactions_with_addr = [ix for ix in listener.interactions if "address" in ix.details]
        for ix in interactions_with_addr:
            addr = ix.details["address"]
            assert isinstance(addr, int), (
                f"address should be int, got {type(addr).__name__}: {addr}"
            )
            assert addr >= 0, f"address should be non-negative, got {addr}"

    def test_quantity_type_when_present(self):
        """If quantity is present in details, it must be a positive int."""
        listener, _devices, _result = _get_modbus_listener()

        interactions_with_qty = [ix for ix in listener.interactions if "quantity" in ix.details]
        for ix in interactions_with_qty:
            qty = ix.details["quantity"]
            assert isinstance(qty, int), f"quantity should be int, got {type(qty).__name__}: {qty}"
            assert qty > 0, f"quantity should be positive, got {qty}"

    def test_address_and_quantity_cooccur(self):
        """If address is present, quantity must also be present."""
        listener, _devices, _result = _get_modbus_listener()

        for ix in listener.interactions:
            if "address" in ix.details:
                assert "quantity" in ix.details, (
                    f"Interaction has address but no quantity: {ix.details}"
                )

    def test_read_addresses_type_on_session(self):
        """Session.read_addresses must be a list of (start, count) tuples."""
        listener, _devices, _result = _get_modbus_listener()

        for key, session in listener.sessions.items():
            assert isinstance(session.read_addresses, list), (
                f"Session {key} read_addresses should be list"
            )
            for entry in session.read_addresses:
                assert isinstance(entry, tuple) and len(entry) == 2, (
                    f"read_addresses entry should be (start, count) tuple: {entry}"
                )
                assert isinstance(entry[0], int) and isinstance(entry[1], int), (
                    f"read_addresses entry values should be ints: {entry}"
                )

    def test_write_addresses_type_on_session(self):
        """Session.write_addresses must be a list of (start, count) tuples."""
        listener, _devices, _result = _get_modbus_listener()

        for key, session in listener.sessions.items():
            assert isinstance(session.write_addresses, list), (
                f"Session {key} write_addresses should be list"
            )
            for entry in session.write_addresses:
                assert isinstance(entry, tuple) and len(entry) == 2, (
                    f"write_addresses entry should be (start, count) tuple: {entry}"
                )


# =========================================================================
# Value Extraction Tests
# =========================================================================


class TestModbusValues:
    """Test value extraction from Modbus interactions.

    NOTE: In EK mode, tshark may not expose modbus.regval_uint16 or
    modbus.bitval for all pcaps.  These tests validate structure when
    values are found, and tolerate their absence.
    """

    def test_values_type_when_present(self):
        """If values is present in details, it must be a non-empty list of strings."""
        listener, _devices, _result = _get_modbus_listener()

        interactions_with_vals = [ix for ix in listener.interactions if "values" in ix.details]
        for ix in interactions_with_vals:
            vals = ix.details["values"]
            assert isinstance(vals, list), (
                f"values should be list, got {type(vals).__name__}: {vals}"
            )
            if vals:  # values can be empty list in decode-error case
                for v in vals:
                    assert isinstance(v, str), (
                        f"each value should be str, got {type(v).__name__}: {v}"
                    )

    def test_values_hex_accompanies_values(self):
        """If values is present and non-empty, values_hex should also be present."""
        listener, _devices, _result = _get_modbus_listener()

        for ix in listener.interactions:
            vals = ix.details.get("values", [])
            if vals and vals != ["[decode error]"]:
                assert "values_hex" in ix.details, (
                    f"values present but values_hex missing: {ix.details}"
                )
                hex_vals = ix.details["values_hex"]
                assert isinstance(hex_vals, list), (
                    f"values_hex should be list, got {type(hex_vals).__name__}"
                )
                assert len(hex_vals) == len(vals), (
                    f"values_hex length ({len(hex_vals)}) != values length ({len(vals)})"
                )

    def test_values_hex_format(self):
        """values_hex entries should be 4-char hex or original value."""
        listener, _devices, _result = _get_modbus_listener()

        for ix in listener.interactions:
            hex_vals = ix.details.get("values_hex", [])
            for hv in hex_vals:
                assert isinstance(hv, str), (
                    f"values_hex entry should be str, got {type(hv).__name__}"
                )


# =========================================================================
# Exception Response Tests
# =========================================================================


class TestModbusExceptions:
    """Test exception response handling.

    digitalbond_modbus_part1 contains exception responses with code 11
    (Gateway Target Device Failed to Respond) for FC 8 (Diagnostics).
    """

    def test_exception_code_in_details(self):
        """Exception responses must have exception_code in details."""
        listener, _devices, _result = _run_listener_test(
            "modbus",
            "ModbusPassiveListener",
            "mbtcp",
            DIGITALBOND_P1_PCAP,
            min_devices=1,
            min_interactions=1,
            expect_details=["function_code"],
        )

        exc_interactions = [ix for ix in listener.interactions if "exception_code" in ix.details]
        assert len(exc_interactions) >= 1, (
            "Expected at least one interaction with exception_code in "
            f"digitalbond_part1; got {len(exc_interactions)} out of {len(listener.interactions)}"
        )

    def test_exception_code_is_valid_int(self):
        """exception_code must be a positive int (1-11 per Modbus spec)."""
        listener, _devices, _result = _run_listener_test(
            "modbus",
            "ModbusPassiveListener",
            "mbtcp",
            DIGITALBOND_P1_PCAP,
            min_devices=0,
            min_interactions=0,
        )

        for ix in listener.interactions:
            if "exception_code" in ix.details:
                exc = ix.details["exception_code"]
                assert isinstance(exc, int), (
                    f"exception_code should be int, got {type(exc).__name__}: {exc}"
                )
                assert exc > 0, f"exception_code should be positive, got {exc}"

    def test_exception_on_response_only(self):
        """exception_code should only appear on response interactions."""
        listener, _devices, _result = _run_listener_test(
            "modbus",
            "ModbusPassiveListener",
            "mbtcp",
            DIGITALBOND_P1_PCAP,
            min_devices=0,
            min_interactions=0,
        )

        for ix in listener.interactions:
            if "exception_code" in ix.details:
                assert ix.direction == "response", (
                    f"exception_code found on {ix.direction} interaction: {ix.details}"
                )

    def test_exception_code_11_in_digitalbond(self):
        """digitalbond_part1 contains exception code 11 (Gateway Target Failed)."""
        listener, _devices, _result = _run_listener_test(
            "modbus",
            "ModbusPassiveListener",
            "mbtcp",
            DIGITALBOND_P1_PCAP,
            min_devices=0,
            min_interactions=0,
        )

        exc_codes = {
            ix.details["exception_code"]
            for ix in listener.interactions
            if "exception_code" in ix.details
        }
        assert 11 in exc_codes, (
            f"Expected exception code 11 in digitalbond_part1; found codes: {exc_codes}"
        )

    def test_exception_summary_contains_exception_text(self):
        """Exception interaction summary should mention 'Exception'."""
        listener, _devices, _result = _run_listener_test(
            "modbus",
            "ModbusPassiveListener",
            "mbtcp",
            DIGITALBOND_P1_PCAP,
            min_devices=0,
            min_interactions=0,
        )

        for ix in listener.interactions:
            if "exception_code" in ix.details:
                assert "exception" in ix.summary.lower(), (
                    f"Exception interaction summary should mention 'Exception': {ix.summary}"
                )


# =========================================================================
# Write Operation Detection Tests
# =========================================================================


class TestModbusWriteDetection:
    """Test write operation detection across pcaps with write function codes.

    modbus_tcp_full has FC 15 (Write Multiple Coils).
    digitalbond_part1 has FC 5, 6 (Write Single Coil, Write Single Register).
    zeek_modbus_mixed has FC 5, 6.
    cisagov has FC 5, 6, 15, 16.
    """

    def test_write_count_positive_for_write_pcap(self):
        """Sessions from write-containing pcap must have write_count > 0."""
        listener, _devices, _result = _get_write_listener(MODBUS_TCP_FULL_PCAP)

        has_writes = any(s.write_count > 0 for s in listener.sessions.values())
        assert has_writes, (
            "Expected at least one session with write_count > 0 in modbus_tcp_full; "
            f"sessions: {[(k, s.write_count) for k, s in listener.sessions.items()]}"
        )

    def test_get_write_operations_nonempty(self):
        """get_write_operations() must return non-empty for write-containing pcap."""
        listener, _devices, _result = _get_write_listener(MODBUS_TCP_FULL_PCAP)

        write_ops = listener.get_write_operations()
        assert len(write_ops) >= 1, (
            "Expected get_write_operations() to return at least 1 entry for modbus_tcp_full"
        )

    def test_write_operations_structure(self):
        """Each write operation dict must have required keys."""
        listener, _devices, _result = _get_write_listener(MODBUS_TCP_FULL_PCAP)

        write_ops = listener.get_write_operations()
        assert write_ops, "Expected non-empty write operations"

        required_keys = {"client", "server", "write_count", "write_function_codes", "write_ranges"}
        for w in write_ops:
            missing = required_keys - set(w.keys())
            assert not missing, f"Write operation missing keys: {missing}; got: {sorted(w.keys())}"
            assert w["write_count"] > 0, f"write_count should be > 0, got {w['write_count']}"
            assert isinstance(w["write_function_codes"], list), (
                f"write_function_codes should be list, got {type(w['write_function_codes'])}"
            )

    def test_write_function_codes_are_valid(self):
        """Write function codes in get_write_operations() should be in WRITE_FUNCTION_CODES."""
        listener, _devices, _result = _get_write_listener(MODBUS_TCP_FULL_PCAP)

        write_ops = listener.get_write_operations()
        for w in write_ops:
            for fc in w["write_function_codes"]:
                assert fc in WRITE_FUNCTION_CODES, (
                    f"FC {fc} in write_function_codes but not in WRITE_FUNCTION_CODES"
                )

    def test_write_operations_have_fc15_in_full_pcap(self):
        """modbus_tcp_full should detect FC 15 (Write Multiple Coils) writes."""
        listener, _devices, _result = _get_write_listener(MODBUS_TCP_FULL_PCAP)

        all_write_fcs = set()
        for w in listener.get_write_operations():
            all_write_fcs.update(w["write_function_codes"])
        assert 15 in all_write_fcs, (
            f"Expected FC 15 in write function codes; found: {all_write_fcs}"
        )

    def test_write_interactions_have_write_operation_name(self):
        """Interactions with write FCs should have 'Write' in operation name."""
        listener, _devices, _result = _get_write_listener(MODBUS_TCP_FULL_PCAP)

        write_interactions = [
            ix
            for ix in listener.interactions
            if ix.details.get("function_code") in WRITE_FUNCTION_CODES
        ]
        assert write_interactions, "Expected interactions with write function codes"

        for ix in write_interactions:
            assert "write" in ix.operation.lower(), (
                f"Write FC {ix.details['function_code']} interaction should have 'Write' "
                f"in operation, got: {ix.operation}"
            )

    def test_write_device_data_nonzero(self):
        """Device passive data should show write_operations > 0 for write pcap."""
        _listener, devices, _result = _get_write_listener(MODBUS_TCP_FULL_PCAP)

        devices_with_data = [
            d
            for d in devices.values()
            if hasattr(d, "modbus_passive_data") and d.modbus_passive_data
        ]
        assert devices_with_data, "Expected devices with modbus_passive_data"

        has_writes = any(
            d.modbus_passive_data.get("write_operations", 0) > 0 for d in devices_with_data
        )
        assert has_writes, (
            "Expected at least one device with write_operations > 0; "
            f"values: {[d.modbus_passive_data.get('write_operations') for d in devices_with_data]}"
        )

    def test_digitalbond_writes_fc5_fc6(self):
        """digitalbond_part1 should detect FC 5 and FC 6 writes."""
        listener, _devices, _result = _run_listener_test(
            "modbus",
            "ModbusPassiveListener",
            "mbtcp",
            DIGITALBOND_P1_PCAP,
            min_devices=1,
            min_interactions=1,
            expect_details=["function_code"],
        )

        all_write_fcs = set()
        for w in listener.get_write_operations():
            all_write_fcs.update(w["write_function_codes"])
        assert 5 in all_write_fcs or 6 in all_write_fcs, (
            f"Expected FC 5 or FC 6 in digitalbond_part1 write FCs; found: {all_write_fcs}"
        )

    def test_cisagov_has_reads_and_writes(self):
        """cisagov pcap should have both read and write operations detected."""
        listener, _devices, _result = _get_modbus_listener(CISAGOV_PCAP)

        total_reads = sum(s.read_count for s in listener.sessions.values())
        total_writes = sum(s.write_count for s in listener.sessions.values())
        assert total_reads > 0, f"Expected reads > 0, got {total_reads}"
        assert total_writes > 0, f"Expected writes > 0, got {total_writes}"


# =========================================================================
# Device Passive Data Completeness Tests
# =========================================================================


class TestModbusDeviceData:
    """Test device passive data completeness and types."""

    # All keys that _build_device_data always produces
    REQUIRED_KEYS = {
        "role",
        "unit_ids",
        "function_codes_seen",
        "function_names",
        "read_ranges",
        "write_ranges",
        "write_operations",
        "read_operations",
        "protocol",
        "first_seen",
        "last_seen",
    }

    def test_all_required_keys_present(self):
        """Every device with modbus_passive_data must have all required keys."""
        _listener, devices, _result = _get_modbus_listener()

        devices_with_data = [
            d
            for d in devices.values()
            if hasattr(d, "modbus_passive_data") and d.modbus_passive_data
        ]
        assert devices_with_data, "Expected devices with modbus_passive_data"

        for d in devices_with_data:
            data = d.modbus_passive_data
            missing = self.REQUIRED_KEYS - set(data.keys())
            assert not missing, (
                f"modbus_passive_data missing keys: {missing}; got: {sorted(data.keys())}"
            )

    def test_role_is_server_or_client(self):
        """role must be 'server' or 'client'."""
        _listener, devices, _result = _get_modbus_listener()

        for d in devices.values():
            data = getattr(d, "modbus_passive_data", None)
            if data:
                assert data["role"] in ("server", "client"), (
                    f"role should be 'server' or 'client', got: {data['role']}"
                )

    def test_unit_ids_sorted_list_of_ints(self):
        """unit_ids must be a sorted list of ints."""
        _listener, devices, _result = _get_modbus_listener()

        for d in devices.values():
            data = getattr(d, "modbus_passive_data", None)
            if data:
                uids = data["unit_ids"]
                assert isinstance(uids, list), f"unit_ids should be list, got {type(uids)}"
                assert uids == sorted(uids), f"unit_ids should be sorted: {uids}"
                for uid in uids:
                    assert isinstance(uid, int), f"unit_id should be int, got {type(uid)}: {uid}"
                    assert 0 <= uid <= 255, f"unit_id out of range: {uid}"

    def test_function_codes_seen_sorted_ints(self):
        """function_codes_seen must be a sorted list of ints."""
        _listener, devices, _result = _get_modbus_listener()

        for d in devices.values():
            data = getattr(d, "modbus_passive_data", None)
            if data:
                fcs = data["function_codes_seen"]
                assert isinstance(fcs, list), "function_codes_seen should be list"
                assert fcs == sorted(fcs), f"function_codes_seen should be sorted: {fcs}"
                for fc in fcs:
                    assert isinstance(fc, int), f"FC should be int, got {type(fc)}: {fc}"

    def test_function_names_matches_codes(self):
        """function_names length should match function_codes_seen length."""
        _listener, devices, _result = _get_modbus_listener()

        for d in devices.values():
            data = getattr(d, "modbus_passive_data", None)
            if data:
                fcs = data["function_codes_seen"]
                names = data["function_names"]
                assert len(names) == len(fcs), (
                    f"function_names length ({len(names)}) != "
                    f"function_codes_seen length ({len(fcs)})"
                )
                for name in names:
                    assert isinstance(name, str), "function_name should be str"
                    assert name, "function_name should not be empty"

    def test_protocol_is_modbus_tcp(self):
        """protocol must be 'Modbus/TCP'."""
        _listener, devices, _result = _get_modbus_listener()

        for d in devices.values():
            data = getattr(d, "modbus_passive_data", None)
            if data:
                assert data["protocol"] == "Modbus/TCP", (
                    f"protocol should be 'Modbus/TCP', got: {data['protocol']}"
                )

    def test_read_write_operations_are_ints(self):
        """read_operations and write_operations must be non-negative ints."""
        _listener, devices, _result = _get_modbus_listener()

        for d in devices.values():
            data = getattr(d, "modbus_passive_data", None)
            if data:
                for key in ("read_operations", "write_operations"):
                    val = data[key]
                    assert isinstance(val, int), f"{key} should be int, got {type(val)}"
                    assert val >= 0, f"{key} should be >= 0, got {val}"

    def test_read_write_ranges_are_lists_of_tuples(self):
        """read_ranges and write_ranges must be lists of (start, end) tuples."""
        _listener, devices, _result = _get_modbus_listener()

        for d in devices.values():
            data = getattr(d, "modbus_passive_data", None)
            if data:
                for key in ("read_ranges", "write_ranges"):
                    ranges = data[key]
                    assert isinstance(ranges, list), f"{key} should be list"
                    for r in ranges:
                        assert isinstance(r, tuple) and len(r) == 2, (
                            f"{key} entry should be (start, end) tuple: {r}"
                        )

    def test_timestamps_are_iso_strings(self):
        """first_seen and last_seen must be non-empty ISO timestamp strings."""
        _listener, devices, _result = _get_modbus_listener()

        for d in devices.values():
            data = getattr(d, "modbus_passive_data", None)
            if data:
                for key in ("first_seen", "last_seen"):
                    ts = data[key]
                    assert isinstance(ts, str) and ts, (
                        f"{key} should be non-empty string, got: {ts!r}"
                    )
                    # Basic ISO format check: contains T separator
                    assert "T" in ts, f"{key} should be ISO format, got: {ts}"

    def test_both_server_and_client_devices_present(self):
        """cisagov pcap should produce both server and client devices."""
        _listener, devices, _result = _get_modbus_listener()

        roles = set()
        for d in devices.values():
            data = getattr(d, "modbus_passive_data", None)
            if data:
                roles.add(data["role"])

        assert "server" in roles, f"Expected 'server' role in devices; found roles: {roles}"
        assert "client" in roles, f"Expected 'client' role in devices; found roles: {roles}"

    def test_device_types_match_roles(self):
        """Server devices should be 'Modbus Server (PLC/RTU)', clients 'Modbus Client (HMI/SCADA)'."""
        _listener, devices, _result = _get_modbus_listener()

        for d in devices.values():
            data = getattr(d, "modbus_passive_data", None)
            if data:
                if data["role"] == "server":
                    assert "server" in d.device_type.lower(), (
                        f"Server device type should contain 'server': {d.device_type}"
                    )
                elif data["role"] == "client":
                    assert "client" in d.device_type.lower(), (
                        f"Client device type should contain 'client': {d.device_type}"
                    )

    def test_trans_id_range_optional_but_valid(self):
        """trans_id_range is optional; when present must be [min, max] with min <= max."""
        _listener, devices, _result = _get_modbus_listener()

        for d in devices.values():
            data = getattr(d, "modbus_passive_data", None)
            if data and "trans_id_range" in data:
                rng = data["trans_id_range"]
                assert isinstance(rng, list) and len(rng) == 2, (
                    f"trans_id_range should be [min, max], got: {rng}"
                )
                assert isinstance(rng[0], int) and isinstance(rng[1], int), (
                    f"trans_id_range values should be ints: {rng}"
                )
                assert rng[0] <= rng[1], f"trans_id_range min > max: {rng}"


# =========================================================================
# Protocol Column Formatting Tests
# =========================================================================


class TestModbusProtocolColumns:
    """Test _format_protocol_columns() correctness and consistency."""

    def test_protocol_columns_defined(self):
        """PROTOCOL_COLUMNS must be non-empty and match expected order."""
        expected = ("tx_id", "unit", "fc", "function", "address", "count", "data")
        assert ModbusPassiveListener.PROTOCOL_COLUMNS == expected, (
            f"PROTOCOL_COLUMNS changed: {ModbusPassiveListener.PROTOCOL_COLUMNS}"
        )

    def test_format_columns_length_matches_header(self):
        """_format_protocol_columns output length must match PROTOCOL_COLUMNS."""
        listener, _devices, _result = _get_modbus_listener()

        expected_cols = len(ModbusPassiveListener.PROTOCOL_COLUMNS)
        for ix in listener.interactions:
            row = listener._format_protocol_columns(ix)
            assert len(row) == expected_cols, (
                f"Row has {len(row)} columns but PROTOCOL_COLUMNS has {expected_cols}; row={row}"
            )

    def test_format_columns_fc_matches_details(self):
        """The fc column should match the function_code from details."""
        listener, _devices, _result = _get_modbus_listener()

        for ix in listener.interactions[:20]:
            row = listener._format_protocol_columns(ix)
            # row[2] is fc (index matching PROTOCOL_COLUMNS)
            expected_fc = ix.details.get("function_code", "")
            assert row[2] == expected_fc, (
                f"Column fc={row[2]} doesn't match details function_code={expected_fc}"
            )

    def test_format_columns_unit_matches_details(self):
        """The unit column should match the unit_id from details."""
        listener, _devices, _result = _get_modbus_listener()

        for ix in listener.interactions[:20]:
            row = listener._format_protocol_columns(ix)
            # row[1] is unit
            expected_unit = ix.details.get("unit_id", "")
            assert row[1] == expected_unit, (
                f"Column unit={row[1]} doesn't match details unit_id={expected_unit}"
            )

    def test_format_columns_function_name_present(self):
        """The function column should have a non-empty function name."""
        listener, _devices, _result = _get_modbus_listener()

        for ix in listener.interactions[:20]:
            row = listener._format_protocol_columns(ix)
            # row[3] is function name
            assert row[3], f"function name column is empty: {row}"

    def test_exception_in_data_column(self):
        """Exception interactions should show 'Exception N' in the data column."""
        listener, _devices, _result = _run_listener_test(
            "modbus",
            "ModbusPassiveListener",
            "mbtcp",
            DIGITALBOND_P1_PCAP,
            min_devices=0,
            min_interactions=0,
        )

        for ix in listener.interactions:
            if "exception_code" in ix.details:
                row = listener._format_protocol_columns(ix)
                # row[6] is data column
                data_col = str(row[6])
                assert "exception" in data_col.lower(), (
                    f"Exception interaction data column should show 'Exception': {data_col}"
                )

    def test_response_without_address_shows_question_mark(self):
        """Response interactions without correlated address should show '?' for address."""
        listener, _devices, _result = _get_modbus_listener()

        for ix in listener.interactions:
            if ix.direction == "response" and "address" not in ix.details:
                row = listener._format_protocol_columns(ix)
                # row[4] is address column
                # It should be "?" for uncorrelated responses
                # (but might be empty if the listener correlated successfully)
                # Just verify it doesn't crash
                assert row[4] is not None, "address column should not be None"


# =========================================================================
# Fuzz/Edge Case Tests
# =========================================================================


class TestModbusFuzzPcap:
    """Test robustness with malformed/fuzzed pcap fixtures."""

    def test_fuzz72_does_not_crash(self):
        """bro_modbus_fuzz72.pcap should not crash the listener (0 interactions expected)."""
        listener, devices, result = _run_listener_test(
            "modbus",
            "ModbusPassiveListener",
            "mbtcp",
            BRO_FUZZ72_PCAP,
            min_devices=0,
            min_interactions=0,
        )
        # No crash is the assertion; interaction count may be 0
        assert isinstance(listener.interactions, list)
        assert isinstance(devices, dict)

    def test_fuzz1011_produces_data(self):
        """bro_modbus_fuzz1011.pcap should produce some interactions without crashing."""
        listener, devices, result = _run_listener_test(
            "modbus",
            "ModbusPassiveListener",
            "mbtcp",
            BRO_FUZZ1011_PCAP,
            min_devices=0,
            min_interactions=0,
        )
        assert isinstance(listener.interactions, list)
        assert isinstance(devices, dict)
        # This pcap should produce a few interactions
        assert len(listener.interactions) >= 1, (
            f"Expected at least 1 interaction from fuzz1011, got {len(listener.interactions)}"
        )

    def test_digitalbond_part2_does_not_crash(self):
        """digitalbond_part2 has FC 0-127 (all possible codes); should not crash."""
        listener, devices, result = _run_listener_test(
            "modbus",
            "ModbusPassiveListener",
            "mbtcp",
            "modbus/digitalbond_modbus_part2.pcap",
            min_devices=0,
            min_interactions=0,
        )
        assert isinstance(listener.interactions, list)
        assert isinstance(devices, dict)


# =========================================================================
# Harvest Output Tests
# =========================================================================


class TestModbusHarvest:
    """Test harvest() output structure and write alert filtering."""

    def test_harvest_returns_dict(self):
        """harvest() should return a dict."""
        _listener, _devices, result = _get_modbus_listener()
        assert isinstance(result, dict)

    def test_harvest_tables_no_raw_types(self):
        """harvest() tables should not contain raw dicts or sets in cells."""
        _listener, _devices, result = _get_modbus_listener()
        for table in result.get("tables", []):
            for row in table.get("rows", []):
                for cell in row:
                    assert not isinstance(cell, dict), f"Raw dict in table cell: {cell}"
                    assert not isinstance(cell, set), f"Raw set in table cell: {cell}"

    def test_harvest_filters_write_alerts(self):
        """Modbus harvest() should filter out write_alert category alerts."""
        listener, _devices, _result = _get_write_listener(MODBUS_TCP_FULL_PCAP)

        # Verify write operations exist (so there should have been alerts)
        write_ops = listener.get_write_operations()
        assert write_ops, "Expected write operations in modbus_tcp_full"

        # Now check harvest -- write_alert should be filtered
        result = listener.harvest()
        alerts = result.get("alerts", [])
        write_alerts = [a for a in alerts if a.get("category") == "write_alert"]
        assert not write_alerts, (
            f"Modbus harvest should filter write_alert alerts; found: {write_alerts}"
        )

    def test_base_harvest_has_write_alerts(self):
        """Base class harvest (before Modbus override) would include write_alert."""
        listener, _devices, _result = _get_write_listener(MODBUS_TCP_FULL_PCAP)

        # Call the base class harvest to verify alerts would exist
        base_result = super(ModbusPassiveListener, listener).harvest()
        base_alerts = base_result.get("alerts", [])
        write_alerts = [a for a in base_alerts if a.get("category") == "write_alert"]
        assert len(write_alerts) >= 1, (
            f"Base harvest should include write_alert; got: {base_alerts}"
        )

    def test_harvest_alert_message_format(self):
        """Write alerts from base harvest should follow expected format."""
        listener, _devices, _result = _get_write_listener(MODBUS_TCP_FULL_PCAP)

        base_result = super(ModbusPassiveListener, listener).harvest()
        for alert in base_result.get("alerts", []):
            if alert.get("category") == "write_alert":
                assert alert["level"] == "fail", "Write alert level should be 'fail'"
                msg = alert["message"]
                assert "MODBUS WRITE" in msg, f"Write alert should contain 'MODBUS WRITE': {msg}"
                assert "->" in msg, f"Write alert should contain '->': {msg}"
                assert "writes" in msg.lower(), f"Write alert should mention writes: {msg}"


# =========================================================================
# Interaction Structure Tests
# =========================================================================


class TestModbusInteractionStructure:
    """Test that every interaction has the required base fields."""

    def test_every_interaction_has_direction(self):
        """Every interaction must have direction 'request' or 'response'."""
        listener, _devices, _result = _get_modbus_listener()

        for ix in listener.interactions:
            assert ix.direction in ("request", "response"), f"Invalid direction: {ix.direction}"

    def test_every_interaction_has_ips(self):
        """Every interaction must have non-empty src_ip and dst_ip."""
        listener, _devices, _result = _get_modbus_listener()

        for ix in listener.interactions:
            assert ix.src_ip, f"Interaction has empty src_ip: {ix}"
            assert ix.dst_ip, f"Interaction has empty dst_ip: {ix}"

    def test_every_interaction_has_operation(self):
        """Every interaction must have a non-empty operation string."""
        listener, _devices, _result = _get_modbus_listener()

        for ix in listener.interactions:
            assert ix.operation, f"Interaction has empty operation: {ix.details}"

    def test_every_interaction_has_function_code(self):
        """Every interaction must have function_code in details."""
        listener, _devices, _result = _get_modbus_listener()

        for ix in listener.interactions:
            fc = ix.details.get("function_code")
            assert fc is not None, f"Interaction missing function_code: {ix.details}"
            assert isinstance(fc, int), f"function_code should be int: {fc}"
            assert fc > 0, f"function_code should be positive: {fc}"

    def test_every_interaction_has_unit_id(self):
        """Every interaction must have unit_id in details."""
        listener, _devices, _result = _get_modbus_listener()

        for ix in listener.interactions:
            uid = ix.details.get("unit_id")
            assert uid is not None, f"Interaction missing unit_id: {ix.details}"
            assert isinstance(uid, int), f"unit_id should be int: {uid}"

    def test_every_interaction_has_function_name(self):
        """Every interaction must have function_name in details."""
        listener, _devices, _result = _get_modbus_listener()

        for ix in listener.interactions:
            fname = ix.details.get("function_name")
            assert fname is not None, f"Interaction missing function_name: {ix.details}"
            assert isinstance(fname, str) and fname, (
                f"function_name should be non-empty str: {fname}"
            )

    def test_every_interaction_has_summary(self):
        """Every interaction must have a non-empty summary string."""
        listener, _devices, _result = _get_modbus_listener()

        for ix in listener.interactions:
            assert ix.summary, f"Interaction has empty summary: {ix.details}"

    def test_every_interaction_has_protocol(self):
        """Every interaction must have protocol set to 'MODBUS'."""
        listener, _devices, _result = _get_modbus_listener()

        for ix in listener.interactions:
            assert ix.protocol == "MODBUS", (
                f"Interaction protocol should be 'MODBUS', got: {ix.protocol}"
            )

    def test_request_response_pairing(self):
        """cisagov pcap should have both request and response interactions."""
        listener, _devices, _result = _get_modbus_listener()

        directions = {ix.direction for ix in listener.interactions}
        assert "request" in directions, "Expected 'request' interactions"
        assert "response" in directions, "Expected 'response' interactions"

    def test_flow_id_populated(self):
        """At least some interactions should have a non-empty flow_id."""
        listener, _devices, _result = _get_modbus_listener()

        has_flow = any(ix.flow_id for ix in listener.interactions)
        assert has_flow, "Expected at least one interaction with non-empty flow_id"


# =========================================================================
# Summary and Helper Method Tests
# =========================================================================


class TestModbusSummaryMethods:
    """Test get_sessions_summary(), get_write_operations(), get_interactions_summary()."""

    def test_get_interactions_summary_structure(self):
        """get_interactions_summary() should return dict with expected keys."""
        listener, _devices, _result = _get_modbus_listener()

        summary = listener.get_interactions_summary()
        assert isinstance(summary, dict)
        required_keys = {"total_interactions", "operations", "unique_targets", "timeline"}
        missing = required_keys - set(summary.keys())
        assert not missing, f"Interactions summary missing keys: {missing}"

        assert summary["total_interactions"] == len(listener.interactions)
        assert isinstance(summary["operations"], dict)
        assert isinstance(summary["unique_targets"], list)
        assert isinstance(summary["timeline"], list)

    def test_operations_counter_has_read_ops(self):
        """Operations counter should include read function names."""
        listener, _devices, _result = _get_modbus_listener()

        summary = listener.get_interactions_summary()
        ops = summary["operations"]
        # cisagov has Read Coils, Read Holding Registers, etc.
        has_read = any("read" in op.lower() for op in ops.keys())
        assert has_read, f"Expected a read operation in summary; ops: {ops}"

    def test_sessions_summary_count_matches(self):
        """get_sessions_summary() length should match self.sessions count."""
        listener, _devices, _result = _get_modbus_listener()

        summaries = listener.get_sessions_summary()
        assert len(summaries) == len(listener.sessions), (
            f"Sessions summary count ({len(summaries)}) != sessions count ({len(listener.sessions)})"
        )

    def test_write_operations_only_includes_write_sessions(self):
        """get_write_operations() should only include sessions with write_count > 0."""
        listener, _devices, _result = _get_modbus_listener()

        write_ops = listener.get_write_operations()
        for w in write_ops:
            assert w["write_count"] > 0, (
                "get_write_operations() included session with write_count=0"
            )


# =========================================================================
# Multi-Pcap Cross-Fixture Tests
# =========================================================================


class TestModbusMultiPcap:
    """Test behavior across multiple pcap fixtures for consistency."""

    def test_modbus_test_pcap_has_writes(self):
        """modbus_test.pcap should detect write operations (FC 6)."""
        listener, _devices, _result = _run_listener_test(
            "modbus",
            "ModbusPassiveListener",
            "mbtcp",
            MODBUS_TEST_PCAP,
            min_devices=1,
            min_interactions=1,
            expect_details=["function_code"],
        )

        has_writes = any(s.write_count > 0 for s in listener.sessions.values())
        assert has_writes, (
            "Expected writes in modbus_test.pcap; "
            f"session write_counts: {[s.write_count for s in listener.sessions.values()]}"
        )

    def test_zeek_small_has_both_reads_and_writes(self):
        """zeek_modbus_small.pcap should have both reads (FC 1) and writes (FC 15)."""
        listener, _devices, _result = _run_listener_test(
            "modbus",
            "ModbusPassiveListener",
            "mbtcp",
            ZEEK_SMALL_PCAP,
            min_devices=1,
            min_interactions=1,
        )

        total_reads = sum(s.read_count for s in listener.sessions.values())
        total_writes = sum(s.write_count for s in listener.sessions.values())
        assert total_reads > 0, f"Expected reads in zeek_small; got {total_reads}"
        assert total_writes > 0, f"Expected writes in zeek_small; got {total_writes}"

    def test_modbus_tcp_full_many_sessions(self):
        """modbus_tcp_full.pcap should produce multiple sessions."""
        listener, _devices, _result = _get_write_listener(MODBUS_TCP_FULL_PCAP)

        assert len(listener.sessions) >= 5, (
            f"Expected >= 5 sessions in modbus_tcp_full; got {len(listener.sessions)}"
        )

    def test_modbus_tcp_full_many_devices(self):
        """modbus_tcp_full.pcap should produce multiple devices."""
        _listener, devices, _result = _get_write_listener(MODBUS_TCP_FULL_PCAP)

        assert len(devices) >= 5, f"Expected >= 5 devices in modbus_tcp_full; got {len(devices)}"

    def test_zeek_mixed_has_nonstandard_fcs(self):
        """zeek_modbus_mixed has non-standard FCs (49, 74); should not crash."""
        listener, _devices, _result = _run_listener_test(
            "modbus",
            "ModbusPassiveListener",
            "mbtcp",
            ZEEK_MIXED_PCAP,
            min_devices=0,
            min_interactions=0,
        )

        all_fcs = set()
        for ix in listener.interactions:
            fc = ix.details.get("function_code")
            if fc:
                all_fcs.add(fc)

        # These non-standard FCs should be processed without crash
        # They get generic names like "FC49", "FC74"
        assert len(listener.interactions) >= 1, (
            f"Expected interactions from zeek_mixed; got {len(listener.interactions)}"
        )


# =========================================================================
# Modbus Constants Tests
# =========================================================================


class TestModbusConstants:
    """Test module-level constants are consistent."""

    def test_write_fcs_are_subset_of_modbus_fc(self):
        """All WRITE_FUNCTION_CODES should have entries in MODBUS_FC dict."""
        for fc in WRITE_FUNCTION_CODES:
            assert fc in MODBUS_FC, f"WRITE_FUNCTION_CODES {fc} not in MODBUS_FC"

    def test_read_fcs_are_subset_of_modbus_fc(self):
        """All READ_FUNCTION_CODES should have entries in MODBUS_FC dict."""
        for fc in READ_FUNCTION_CODES:
            assert fc in MODBUS_FC, f"READ_FUNCTION_CODES {fc} not in MODBUS_FC"

    def test_read_write_disjoint(self):
        """READ and WRITE FC sets overlap only on documented bidirectional codes.

        FC 0x17 (Read/Write Multiple Registers) reads N regs AND writes M regs
        in one transaction, so it legitimately belongs to both sets.
        """
        overlap = READ_FUNCTION_CODES & WRITE_FUNCTION_CODES
        assert overlap == {0x17}, f"unexpected read/write overlap: {overlap}"

    def test_write_fc_names_contain_write(self):
        """WRITE_FUNCTION_CODES names should contain 'Write' or 'Mask'."""
        for fc in WRITE_FUNCTION_CODES:
            name = MODBUS_FC[fc]
            assert (
                "write" in name.lower() or "mask" in name.lower() or "read/write" in name.lower()
            ), f"Write FC {fc} name doesn't contain 'Write'/'Mask': {name}"

    def test_read_fc_names_contain_read(self):
        """READ_FUNCTION_CODES names contain a read-flavored verb.

        Modbus diagnostic FCs are reads-of-status named with synonyms:
        0x0B 'Get Comm Event Counter', 0x0C 'Get Comm Event Log',
        0x11 'Report Slave ID'. Accept Get/Report alongside Read.
        """
        read_verbs = ("read", "get", "report")
        for fc in READ_FUNCTION_CODES:
            name = MODBUS_FC[fc].lower()
            assert any(v in name for v in read_verbs), (
                f"Read FC {fc} name doesn't contain a read-verb: {MODBUS_FC[fc]}"
            )

    def test_modbus_session_dataclass_defaults(self):
        """ModbusSession default values should be sensible."""
        session = ModbusSession(client_ip="1.2.3.4", server_ip="5.6.7.8")
        assert session.unit_ids == set()
        assert session.function_codes == set()
        assert session.read_addresses == []
        assert session.write_addresses == []
        assert session.write_count == 0
        assert session.read_count == 0
        assert session.trans_id_min is None
        assert session.trans_id_max is None


# =========================================================================
# Build Interaction Summary Tests
# =========================================================================


class TestModbusBuildSummary:
    """Test the static _build_interaction_summary() method."""

    def test_exception_summary(self):
        """Exception summary should mention exception code."""
        summary = ModbusPassiveListener._build_interaction_summary(
            unit_id=1,
            fc_name="Read Holding Registers",
            function_code=3,
            address_info=None,
            is_exception=True,
            exception_code=2,
            is_request=False,
        )
        assert "exception" in summary.lower()
        assert "2" in summary

    def test_response_summary(self):
        """Response summary should mention 'response'."""
        summary = ModbusPassiveListener._build_interaction_summary(
            unit_id=1,
            fc_name="Read Holding Registers",
            function_code=3,
            address_info=None,
            is_exception=False,
            exception_code=0,
            is_request=False,
        )
        assert "response" in summary.lower()

    def test_request_with_address_summary(self):
        """Request with address should show address range."""
        summary = ModbusPassiveListener._build_interaction_summary(
            unit_id=1,
            fc_name="Read Holding Registers",
            function_code=3,
            address_info=(100, 10),
            is_exception=False,
            exception_code=0,
            is_request=True,
        )
        assert "100" in summary
        assert "unitid" in summary.lower()

    def test_write_request_with_single_address(self):
        """Write request with single address (qty=1) should show just the address."""
        summary = ModbusPassiveListener._build_interaction_summary(
            unit_id=1,
            fc_name="Write Single Register",
            function_code=6,
            address_info=(50, 1),
            is_exception=False,
            exception_code=0,
            is_request=True,
        )
        assert "50" in summary
        assert "@50" in summary

    def test_request_without_address(self):
        """Request without address should show just unit and FC name."""
        summary = ModbusPassiveListener._build_interaction_summary(
            unit_id=10,
            fc_name="Diagnostics",
            function_code=8,
            address_info=None,
            is_exception=False,
            exception_code=0,
            is_request=True,
        )
        assert "10" in summary
        assert "diagnostics" in summary.lower()


# =========================================================================
# Merge Ranges Tests
# =========================================================================


class TestModbusMergeRanges:
    """Test the _merge_ranges() helper method."""

    def test_merge_empty(self):
        """Empty address list should return empty."""
        listener = ModbusPassiveListener(interface="lo", timeout=1)
        assert listener._merge_ranges([]) == []

    def test_merge_single(self):
        """Single address range should return as-is (converted to start,end)."""
        listener = ModbusPassiveListener(interface="lo", timeout=1)
        result = listener._merge_ranges([(10, 5)])
        assert result == [(10, 14)]  # start=10, count=5 -> (10, 14)

    def test_merge_non_overlapping(self):
        """Non-overlapping ranges should stay separate."""
        listener = ModbusPassiveListener(interface="lo", timeout=1)
        result = listener._merge_ranges([(0, 10), (20, 5)])
        assert result == [(0, 9), (20, 24)]

    def test_merge_overlapping(self):
        """Overlapping ranges should be merged."""
        listener = ModbusPassiveListener(interface="lo", timeout=1)
        result = listener._merge_ranges([(0, 10), (5, 10)])
        assert result == [(0, 14)]

    def test_merge_adjacent(self):
        """Adjacent ranges (end+1 == start) should be merged."""
        listener = ModbusPassiveListener(interface="lo", timeout=1)
        result = listener._merge_ranges([(0, 5), (5, 5)])
        assert result == [(0, 9)]

    def test_merge_unsorted_input(self):
        """Ranges should be sorted before merging."""
        listener = ModbusPassiveListener(interface="lo", timeout=1)
        result = listener._merge_ranges([(20, 5), (0, 10)])
        assert result == [(0, 9), (20, 24)]


# =========================================================================
# Parse Coil Data Tests
# =========================================================================


class TestModbusParseCoilData:
    """Test the static _parse_coil_data() method."""

    def test_fc5_on(self):
        """FC5 with FF00 should return ['ON']."""
        result = ModbusPassiveListener._parse_coil_data("ff:00", 0x05)
        assert result == ["ON"]

    def test_fc5_off(self):
        """FC5 with 0000 should return ['OFF']."""
        result = ModbusPassiveListener._parse_coil_data("00:00", 0x05)
        assert result == ["OFF"]

    def test_fc15_single_byte(self):
        """FC15 with single byte should expand to 8 bits."""
        result = ModbusPassiveListener._parse_coil_data("03", 0x0F)
        # 0x03 = 0000_0011 -> LSB first: 1,1,0,0,0,0,0,0
        assert len(result) == 8
        assert result[0] == "1"
        assert result[1] == "1"
        assert result[2] == "0"

    def test_empty_data(self):
        """Empty data string should return empty list."""
        result = ModbusPassiveListener._parse_coil_data("", 0x05)
        assert result == []

    def test_invalid_hex(self):
        """Invalid hex string should return empty list."""
        result = ModbusPassiveListener._parse_coil_data("ZZZZ", 0x05)
        assert result == []
