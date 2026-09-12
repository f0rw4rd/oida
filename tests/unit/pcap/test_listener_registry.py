"""
Tests for the PCAP listener registry (listener_registry.py).

Validates listener registration, name resolution, filtering by protocol/tag/
category, quick presets, exclusion logic, and lazy listener instantiation.
"""

from oida.protocols.pcap.listener_registry import (
    CATEGORIES,
    LISTENER_REGISTRY,
    QUICK_LISTENERS,
    create_listeners,
    list_listeners,
    resolve_listener_names,
)


# ---------------------------------------------------------------------------
# Registry structure
# ---------------------------------------------------------------------------


class TestRegistryStructure:
    """Validate the LISTENER_REGISTRY dict structure."""

    def test_registry_is_nonempty(self):
        assert len(LISTENER_REGISTRY) > 0

    def test_every_entry_has_required_keys(self):
        required = {"module", "class", "category", "tags"}
        for name, info in LISTENER_REGISTRY.items():
            missing = required - set(info.keys())
            assert not missing, f"Listener '{name}' missing keys: {missing}"

    def test_tags_are_sets(self):
        for name, info in LISTENER_REGISTRY.items():
            assert isinstance(info["tags"], set), f"'{name}' tags should be a set"

    def test_every_listener_name_is_in_own_tags(self):
        """Each listener name should appear in its own tag set or category tag."""
        for name, info in LISTENER_REGISTRY.items():
            # The name itself OR the category should be in tags
            assert name in info["tags"] or info["category"] in info["tags"], (
                f"'{name}' not findable by its own name or category in tags"
            )

    def test_categories_derived_correctly(self):
        """CATEGORIES should contain every unique category value."""
        expected = {info["category"] for info in LISTENER_REGISTRY.values()}
        assert CATEGORIES == expected

    def test_known_categories_present(self):
        for cat in ("credential", "network", "ics", "routing", "fhrp", "discovery"):
            assert cat in CATEGORIES, f"Expected category '{cat}' in CATEGORIES"


# ---------------------------------------------------------------------------
# QUICK_LISTENERS preset
# ---------------------------------------------------------------------------


class TestQuickListeners:
    """Validate the QUICK_LISTENERS preset."""

    def test_quick_listeners_is_nonempty(self):
        assert len(QUICK_LISTENERS) > 0

    def test_quick_listeners_are_valid_names(self):
        for name in QUICK_LISTENERS:
            assert name in LISTENER_REGISTRY, f"Quick listener '{name}' not in registry"

    def test_quick_listeners_include_core_ics(self):
        for proto in ("modbus", "iec104", "opcua", "s7comm", "dnp3"):
            assert proto in QUICK_LISTENERS, f"Expected '{proto}' in quick preset"

    def test_quick_listeners_include_core_network(self):
        for proto in ("dns", "tls", "http", "ftp"):
            assert proto in QUICK_LISTENERS, f"Expected '{proto}' in quick preset"


# ---------------------------------------------------------------------------
# list_listeners()
# ---------------------------------------------------------------------------


class TestListListeners:
    """Validate list_listeners() output."""

    def test_returns_list(self):
        result = list_listeners()
        assert isinstance(result, list)

    def test_result_is_sorted_by_name(self):
        result = list_listeners()
        names = [entry["name"] for entry in result]
        assert names == sorted(names)

    def test_entry_has_expected_keys(self):
        result = list_listeners()
        for entry in result:
            for key in ("name", "class", "category", "tags"):
                assert key in entry, f"Entry missing key '{key}': {entry}"

    def test_tags_are_sorted_lists(self):
        result = list_listeners()
        for entry in result:
            assert isinstance(entry["tags"], list)
            assert entry["tags"] == sorted(entry["tags"])

    def test_count_matches_registry(self):
        result = list_listeners()
        assert len(result) == len(LISTENER_REGISTRY)


# ---------------------------------------------------------------------------
# resolve_listener_names() — no filters
# ---------------------------------------------------------------------------


class TestResolveNoFilters:
    """resolve_listener_names() with no arguments returns all listeners."""

    def test_no_filters_returns_all(self):
        names = resolve_listener_names()
        assert names == set(LISTENER_REGISTRY.keys())

    def test_no_filters_returns_set(self):
        names = resolve_listener_names()
        assert isinstance(names, set)


# ---------------------------------------------------------------------------
# resolve_listener_names() — protocol filter
# ---------------------------------------------------------------------------


class TestResolveByProtocol:
    """Filter by protocol name or tag."""

    def test_single_name_exact(self):
        names = resolve_listener_names(protocols=["modbus"])
        assert "modbus" in names

    def test_single_name_returns_only_matches(self):
        names = resolve_listener_names(protocols=["modbus"])
        # Should return only modbus (exact name match)
        assert names == {"modbus"}

    def test_tag_match_returns_multiple(self):
        """The 'ics' tag matches all ICS listeners."""
        names = resolve_listener_names(protocols=["ics"])
        assert len(names) > 5
        for expected in ("modbus", "iec104", "opcua", "s7comm", "dnp3"):
            assert expected in names, f"Expected '{expected}' in ICS tag results"

    def test_credential_tag_matches(self):
        names = resolve_listener_names(protocols=["credential"])
        assert "ftp" in names
        assert "telnet" in names
        assert "smtp" in names

    def test_multiple_protocols(self):
        names = resolve_listener_names(protocols=["ftp", "telnet"])
        assert "ftp" in names
        assert "telnet" in names

    def test_case_insensitive(self):
        names_lower = resolve_listener_names(protocols=["modbus"])
        names_upper = resolve_listener_names(protocols=["Modbus"])
        assert names_lower == names_upper


# ---------------------------------------------------------------------------
# resolve_listener_names() — category filter
# ---------------------------------------------------------------------------


class TestResolveByCategory:
    """Filter by category name."""

    def test_ics_category(self):
        names = resolve_listener_names(category=["ics"])
        assert len(names) > 5
        assert "modbus" in names
        assert "ftp" not in names

    def test_credential_category(self):
        names = resolve_listener_names(category=["credential"])
        assert "ftp" in names
        assert "telnet" in names
        assert "modbus" not in names

    def test_routing_category(self):
        names = resolve_listener_names(category=["routing"])
        assert "ospf" in names
        assert "eigrp" in names

    def test_fhrp_category(self):
        names = resolve_listener_names(category=["fhrp"])
        assert "hsrp" in names
        assert "vrrp" in names

    def test_discovery_category(self):
        names = resolve_listener_names(category=["discovery"])
        assert "lldp" in names
        assert "cdp" in names

    def test_multiple_categories(self):
        names = resolve_listener_names(category=["ics", "credential"])
        assert "modbus" in names
        assert "ftp" in names


# ---------------------------------------------------------------------------
# resolve_listener_names() — quick preset
# ---------------------------------------------------------------------------


class TestResolveQuick:
    """Quick preset overrides other filters."""

    def test_quick_returns_preset(self):
        names = resolve_listener_names(quick=True)
        assert names == QUICK_LISTENERS

    def test_quick_overrides_protocols(self):
        """Quick flag should take priority when set."""
        names = resolve_listener_names(protocols=["ftp"], quick=True)
        assert names == QUICK_LISTENERS


# ---------------------------------------------------------------------------
# resolve_listener_names() — exclude
# ---------------------------------------------------------------------------


class TestResolveExclude:
    """Exclusion logic."""

    def test_exclude_by_name(self):
        names = resolve_listener_names(exclude=["ftp"])
        assert "ftp" not in names
        assert "telnet" in names  # others still present

    def test_exclude_by_tag(self):
        names = resolve_listener_names(exclude=["routing"])
        assert "ospf" not in names
        assert "eigrp" not in names
        assert "modbus" in names  # non-routing still present

    def test_exclude_by_category(self):
        names = resolve_listener_names(exclude=["fhrp"])
        assert "hsrp" not in names
        assert "vrrp" not in names
        assert "glbp" not in names

    def test_exclude_combined_with_protocol_filter(self):
        names = resolve_listener_names(protocols=["ics"], exclude=["modbus"])
        assert "modbus" not in names
        assert "iec104" in names

    def test_exclude_multiple(self):
        names = resolve_listener_names(exclude=["routing", "fhrp"])
        assert "ospf" not in names
        assert "hsrp" not in names
        assert "modbus" in names


# ---------------------------------------------------------------------------
# create_listeners()
# ---------------------------------------------------------------------------


class TestCreateListeners:
    """Lazy listener instantiation."""

    def test_returns_dict(self):
        listeners = create_listeners({"dns"})
        assert isinstance(listeners, dict)

    def test_creates_requested_listener(self):
        listeners = create_listeners({"dns"})
        assert "dns" in listeners

    def test_unknown_name_skipped(self):
        listeners = create_listeners({"dns", "nonexistent_protocol_xyz"})
        assert "dns" in listeners
        assert "nonexistent_protocol_xyz" not in listeners

    def test_empty_set_returns_empty(self):
        listeners = create_listeners(set())
        assert listeners == {}

    def test_multiple_listeners_created(self):
        listeners = create_listeners({"dns", "ftp", "modbus"})
        assert len(listeners) >= 2  # at least dns and ftp should succeed

    def test_listener_has_process_packet_method(self):
        listeners = create_listeners({"dns"})
        if "dns" in listeners:
            assert hasattr(listeners["dns"], "process_packet")

    def test_listener_has_protocol_name(self):
        listeners = create_listeners({"dns"})
        if "dns" in listeners:
            assert listeners["dns"].PROTOCOL_NAME == "dns"

    def test_import_failure_is_surfaced_as_warning_not_silent(self, monkeypatch):
        """G6 review regression: a listener that fails to instantiate (e.g. a
        broken module path / missing dependency / bad class name) must not be
        silently dropped with only a debug-level log line -- that makes a
        partially-loaded listener set look like full, successful coverage to
        an operator who isn't running with debug verbosity. It must surface
        via logger.warning().
        """
        import copy

        from oida.protocols.pcap import listener_registry as reg_mod

        broken_registry = copy.deepcopy(reg_mod.LISTENER_REGISTRY)
        broken_registry["dns"] = {
            "module": "oida.pcap.listeners.does_not_exist_xyz",
            "class": "NoSuchListener",
        }
        monkeypatch.setattr(reg_mod, "LISTENER_REGISTRY", broken_registry)

        warnings = []

        class FakeLogger:
            def debug(self, *a, **k):
                pass

            def warning(self, *a, **k):
                warnings.append((a, k))

        listeners = create_listeners({"dns"}, logger=FakeLogger())

        assert "dns" not in listeners
        assert warnings, "expected create_listeners to call logger.warning() on failure"
        # The warning must actually name the failed listener, not just a count.
        assert any("dns" in str(a) for a, _k in warnings)
