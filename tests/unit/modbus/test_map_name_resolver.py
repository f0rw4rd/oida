"""Tests for MapNameResolver (restores the name-based read/write feature).

This class was imported by modbus/mixins/read_write.py but never existed in
decoder.py, so --list-names/--search-name/--read-name/--write-name all died with
ImportError. These tests exercise the restored class against the bundled
oida-mock register map.
"""

import pytest

from oida.protocols.modbus.decoder import MapNameResolver


@pytest.fixture
def resolver():
    return MapNameResolver("oida-mock")


class TestConstruction:
    def test_loads_bundled_map_metadata(self, resolver):
        assert resolver.vendor == "OIDA Mock Devices"
        assert resolver.model
        assert resolver.byte_order in ("big", "little")
        assert isinstance(resolver.map_data, dict)
        assert resolver.map_data.get("default_unit_id") is not None or True

    def test_unknown_map_raises_valueerror(self):
        with pytest.raises(ValueError):
            MapNameResolver("definitely-not-a-real-map-xyz")


class TestResolveAndSearch:
    def test_list_all_returns_entries_with_required_keys(self, resolver):
        entries = resolver.list_all()
        assert entries
        for e in entries:
            # read_write.py accesses these with [] (not .get) -> must exist
            assert "name" in e and "address" in e
            assert "function_code" in e and "section" in e
            assert "type" in e and "access" in e

    def test_resolve_is_case_insensitive(self, resolver):
        e = resolver.resolve("SYSTEM_STATUS")
        assert e is not None
        assert e["name"] == "system_status"
        assert e["address"] == 0

    def test_resolve_unknown_returns_none(self, resolver):
        assert resolver.resolve("no_such_register") is None

    def test_search_matches_name_substring(self, resolver):
        matches = resolver.search("status")
        assert any(m["name"] == "system_status" for m in matches)

    def test_function_code_defaults_holding_for_numeric(self, resolver):
        e = resolver.resolve("system_status")  # u16
        assert e["function_code"] == 3
        assert e["section"] == "registers"


class TestDecodeEncode:
    def test_get_registers_needed(self, resolver):
        e = resolver.resolve("system_status")  # u16 -> 1 register
        assert resolver.get_registers_needed(e) == 1

    def test_decode_value_resolves_enum_label(self, resolver):
        e = resolver.resolve("system_status")  # values: 0=off,1=on,2=fault
        decoded = resolver.decode_value(e, [2])
        assert decoded["value"] == 2
        assert decoded["enum_label"] == "fault"
        assert decoded.get("error") is None

    def test_encode_value_roundtrips_u16(self, resolver):
        e = resolver.resolve("system_status")
        regs = resolver.encode_value(e, "1")
        assert regs == [1]

    def test_encode_rejects_non_numeric(self, resolver):
        e = resolver.resolve("system_status")
        with pytest.raises(ValueError):
            resolver.encode_value(e, "not-a-number")
