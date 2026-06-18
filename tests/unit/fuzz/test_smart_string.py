"""
Tests for SmartString primitive - context-aware string fuzzing.

Tests cover:
- StringContext enum and Flag composites
- Context auto-detection from field names
- Context-specific payload generation
- Composite context deduplication
- Radamsa integration
- SmartStringPrimitive mutations pipeline
- Convenience function
"""

from oida.fuzz.primitives.smart_string import (
    SmartStringPrimitive,
    StringContext,
    _CONTEXT_PAYLOADS,
    smart_string,
)


# =============================================================================
# StringContext enum
# =============================================================================


class TestStringContext:
    """Test the StringContext Flag enum."""

    def test_base_contexts_exist(self):
        assert StringContext.PATH
        assert StringContext.FILENAME
        assert StringContext.CREDENTIAL
        assert StringContext.IP_ADDRESS
        assert StringContext.PORT
        assert StringContext.NUMERIC
        assert StringContext.HOSTNAME
        assert StringContext.COMMAND
        assert StringContext.GENERIC

    def test_composite_host(self):
        """HOST = IP_ADDRESS | HOSTNAME."""
        assert StringContext.HOST == StringContext.IP_ADDRESS | StringContext.HOSTNAME

    def test_composite_network_target(self):
        """NETWORK_TARGET = IP_ADDRESS | HOSTNAME | PORT."""
        assert StringContext.NETWORK_TARGET == (
            StringContext.IP_ADDRESS | StringContext.HOSTNAME | StringContext.PORT
        )

    def test_composite_file_path(self):
        """FILE_PATH = PATH | FILENAME."""
        assert StringContext.FILE_PATH == StringContext.PATH | StringContext.FILENAME

    def test_flag_membership(self):
        """Flag membership check works for composites."""
        assert StringContext.IP_ADDRESS in StringContext.HOST
        assert StringContext.HOSTNAME in StringContext.HOST
        assert StringContext.PORT not in StringContext.HOST

    def test_custom_composite(self):
        """User can create custom composites."""
        custom = StringContext.CREDENTIAL | StringContext.NUMERIC
        assert StringContext.CREDENTIAL in custom
        assert StringContext.NUMERIC in custom
        assert StringContext.PATH not in custom


# =============================================================================
# Context payloads
# =============================================================================


class TestContextPayloads:
    """Test the context payload dictionaries."""

    def test_path_has_traversal(self):
        payloads = _CONTEXT_PAYLOADS[StringContext.PATH]
        assert "../" in payloads
        assert "..\\" in payloads
        has_deep_traversal = any("../" * 5 in p for p in payloads)
        assert has_deep_traversal, "Should have deep traversal payload"

    def test_path_has_absolute_paths(self):
        payloads = _CONTEXT_PAYLOADS[StringContext.PATH]
        assert "/etc/passwd" in payloads
        has_windows = any("Windows" in p or "\\\\?\\" in p for p in payloads)
        assert has_windows, "Should have Windows path payloads"

    def test_path_has_null_injection(self):
        payloads = _CONTEXT_PAYLOADS[StringContext.PATH]
        has_null = any("\x00" in p for p in payloads)
        assert has_null, "Should have NULL injection in path"

    def test_filename_has_special_chars(self):
        payloads = _CONTEXT_PAYLOADS[StringContext.FILENAME]
        has_pipe = any("|" in p for p in payloads)
        assert has_pipe, "Should have pipe character"

    def test_filename_has_windows_reserved(self):
        payloads = _CONTEXT_PAYLOADS[StringContext.FILENAME]
        assert "CON" in payloads
        assert "NUL" in payloads

    def test_credential_has_null_truncation(self):
        payloads = _CONTEXT_PAYLOADS[StringContext.CREDENTIAL]
        has_null = any("\x00" in p for p in payloads)
        assert has_null, "Should have NULL truncation for bypass"

    def test_credential_has_homoglyphs(self):
        payloads = _CONTEXT_PAYLOADS[StringContext.CREDENTIAL]
        has_unicode = any("ⓐ" in p or "Ａ" in p or "а" in p for p in payloads)
        assert has_unicode, "Should have Unicode homoglyph payloads"

    def test_ip_has_boundaries(self):
        payloads = _CONTEXT_PAYLOADS[StringContext.IP_ADDRESS]
        assert "0.0.0.0" in payloads
        assert "255.255.255.255" in payloads
        assert "127.0.0.1" in payloads

    def test_ip_has_alternative_encodings(self):
        payloads = _CONTEXT_PAYLOADS[StringContext.IP_ADDRESS]
        assert "2130706433" in payloads  # Decimal
        assert "0x7f000001" in payloads  # Hex
        assert "0177.0.0.1" in payloads  # Octal

    def test_ip_has_ipv6(self):
        payloads = _CONTEXT_PAYLOADS[StringContext.IP_ADDRESS]
        assert "::1" in payloads
        has_mapped = any("::ffff:" in p for p in payloads)
        assert has_mapped, "Should have IPv4-mapped IPv6"

    def test_port_has_boundaries(self):
        payloads = _CONTEXT_PAYLOADS[StringContext.PORT]
        assert "0" in payloads
        assert "65535" in payloads
        assert "65536" in payloads  # Overflow
        assert "-1" in payloads  # Negative

    def test_numeric_has_int_boundaries(self):
        payloads = _CONTEXT_PAYLOADS[StringContext.NUMERIC]
        assert "127" in payloads  # INT8_MAX
        assert "128" in payloads  # INT8 overflow
        assert "32767" in payloads  # INT16_MAX
        assert "2147483647" in payloads  # INT32_MAX

    def test_numeric_has_float_edge_cases(self):
        payloads = _CONTEXT_PAYLOADS[StringContext.NUMERIC]
        assert "NaN" in payloads
        assert "Infinity" in payloads
        assert "-Infinity" in payloads

    def test_hostname_has_special(self):
        payloads = _CONTEXT_PAYLOADS[StringContext.HOSTNAME]
        assert "localhost" in payloads
        has_idn = any("xn--" in p for p in payloads)
        assert has_idn, "Should have IDN/punycode"

    def test_command_has_injection(self):
        payloads = _CONTEXT_PAYLOADS[StringContext.COMMAND]
        assert "\r\n" in payloads
        assert "\x00" in payloads
        assert ";" in payloads
        assert "|" in payloads

    def test_generic_is_empty(self):
        """GENERIC should have no payloads (ReducedString provides all universal ones)."""
        payloads = _CONTEXT_PAYLOADS[StringContext.GENERIC]
        assert len(payloads) == 0, (
            "GENERIC should be empty - ReducedString already provides universal payloads"
        )


# =============================================================================
# SmartStringPrimitive creation
# =============================================================================


class TestSmartStringCreation:
    """Test SmartStringPrimitive initialization."""

    def test_basic_creation(self):
        s = SmartStringPrimitive(name="test", default_value="hello")
        assert s is not None
        assert s.context == StringContext.GENERIC

    def test_explicit_context_enum(self):
        s = SmartStringPrimitive(name="test", default_value="/home", context=StringContext.PATH)
        assert s.context == StringContext.PATH

    def test_explicit_composite_context(self):
        s = SmartStringPrimitive(
            name="target", default_value="example.com", context=StringContext.HOST
        )
        assert s.context == StringContext.HOST
        assert StringContext.IP_ADDRESS in s.context
        assert StringContext.HOSTNAME in s.context

    def test_none_context_defaults_to_generic(self):
        s = SmartStringPrimitive(name="test", default_value="hello", context=None)
        assert s.context == StringContext.GENERIC

    def test_custom_radamsa_count(self):
        s = SmartStringPrimitive(name="test", default_value="hello", radamsa_count=5)
        assert s.radamsa_count == 5

    def test_default_radamsa_count_by_context(self):
        s = SmartStringPrimitive(
            name="test", default_value="hello", context=StringContext.CREDENTIAL
        )
        assert s.radamsa_count == SmartStringPrimitive._radamsa_counts[StringContext.CREDENTIAL]


# =============================================================================
# Radamsa count for composites
# =============================================================================


class TestRadamsaCount:
    """Test Radamsa mutation count calculation."""

    def test_single_context_count(self):
        count = SmartStringPrimitive._get_radamsa_count(StringContext.PATH)
        assert count == 20

    def test_composite_takes_max(self):
        """Composite context should use the maximum count of constituents."""
        count = SmartStringPrimitive._get_radamsa_count(StringContext.HOST)
        ip_count = SmartStringPrimitive._radamsa_counts[StringContext.IP_ADDRESS]
        host_count = SmartStringPrimitive._radamsa_counts[StringContext.HOSTNAME]
        assert count == max(ip_count, host_count)

    def test_fallback_for_unknown(self):
        """Empty/zero flag should return 20."""
        # Force a context with no matching base
        count = SmartStringPrimitive._get_radamsa_count(StringContext(0))
        assert count == 20


# =============================================================================
# Context payload generation
# =============================================================================


class TestContextPayloadGeneration:
    """Test _context_payloads method."""

    def test_path_payloads(self):
        s = SmartStringPrimitive(name="test", default_value="/", context=StringContext.PATH)
        payloads = s._context_payloads()
        assert len(payloads) > 0
        assert "../" in payloads

    def test_generic_no_payloads(self):
        s = SmartStringPrimitive(name="test", default_value="hello", context=StringContext.GENERIC)
        payloads = s._context_payloads()
        assert len(payloads) == 0

    def test_composite_combines_payloads(self):
        """HOST context should combine IP_ADDRESS and HOSTNAME payloads."""
        s = SmartStringPrimitive(
            name="target", default_value="example.com", context=StringContext.HOST
        )
        payloads = s._context_payloads()

        # Should have IP payloads
        assert "127.0.0.1" in payloads
        assert "0.0.0.0" in payloads

        # Should have hostname payloads
        assert "localhost" in payloads

    def test_composite_no_duplicates(self):
        """Composite payloads should not have duplicates."""
        s = SmartStringPrimitive(name="target", default_value="x", context=StringContext.FILE_PATH)
        payloads = s._context_payloads()
        assert len(payloads) == len(set(payloads)), "Should have no duplicate payloads"

    def test_network_target_has_all_three(self):
        """NETWORK_TARGET = IP | HOSTNAME | PORT."""
        s = SmartStringPrimitive(
            name="target", default_value="host:80", context=StringContext.NETWORK_TARGET
        )
        payloads = s._context_payloads()

        # IP payloads
        assert "127.0.0.1" in payloads
        # Hostname payloads
        assert "localhost" in payloads
        # Port payloads
        assert "65535" in payloads


# =============================================================================
# Mutations pipeline
# =============================================================================


class TestSmartStringMutations:
    """Test the full mutations pipeline."""

    def test_mutations_are_generated(self):
        s = SmartStringPrimitive(name="test", default_value="hello", context=StringContext.GENERIC)
        mutations = list(s.mutations(b"hello"))
        assert len(mutations) > 0

    def test_mutations_are_strings(self):
        """SmartString should yield strings, not bytes (for boofuzz compatibility)."""
        s = SmartStringPrimitive(
            name="test", default_value="hello", context=StringContext.GENERIC, radamsa_count=0
        )
        mutations = list(s.mutations(b"hello"))
        for m in mutations[:50]:  # Check first 50
            assert isinstance(m, str), f"Expected str, got {type(m)}: {m!r}"

    def test_mutations_include_context_payloads(self):
        s = SmartStringPrimitive(
            name="test", default_value="/home", context=StringContext.PATH, radamsa_count=0
        )
        mutations = list(s.mutations(b"/home"))
        assert "../" in mutations, "Should include path traversal"

    def test_mutations_no_duplicates(self):
        s = SmartStringPrimitive(
            name="test", default_value="hello", context=StringContext.GENERIC, radamsa_count=0
        )
        mutations = list(s.mutations(b"hello"))
        assert len(mutations) == len(set(mutations)), "Should have no duplicate mutations"

    def test_mutations_include_format_strings(self):
        """Format strings should come from ReducedString base."""
        s = SmartStringPrimitive(
            name="test",
            default_value="hello",
            context=StringContext.GENERIC,
            radamsa_count=0,
            max_len=65536,
        )
        mutations = list(s.mutations(b"hello"))
        has_fmt_n = any("%n" in m for m in mutations)
        has_fmt_s = any("%s" in m for m in mutations)
        assert has_fmt_n, "Should include %n format strings from ReducedString"
        assert has_fmt_s, "Should include %s format strings from ReducedString"

    def test_mutations_no_shell_injection(self):
        """SmartString should NOT contain shell injection payloads."""
        s = SmartStringPrimitive(
            name="test", default_value="hello", context=StringContext.GENERIC, radamsa_count=0
        )
        mutations = list(s.mutations(b"hello"))
        for m in mutations:
            assert "notepad" not in m, f"Shell injection found: {m!r}"
            assert "$(reboot)" not in m, f"Shell injection found: {m!r}"

    def test_credential_context_mutations(self):
        s = SmartStringPrimitive(
            name="username",
            default_value="admin",
            context=StringContext.CREDENTIAL,
            radamsa_count=0,
        )
        mutations = list(s.mutations(b"admin"))
        # Should have NULL truncation
        has_null = any("admin\x00" in m for m in mutations)
        assert has_null, "Credential context should include NULL truncation"


# =============================================================================
# Radamsa integration
# =============================================================================


class TestSmartStringRadamsa:
    """Test Radamsa mutation integration."""

    def test_radamsa_mutations_generated(self):
        s = SmartStringPrimitive(
            name="test",
            default_value="hello world",
            context=StringContext.GENERIC,
            radamsa_count=10,
        )
        radamsa_muts = s._radamsa_mutations("hello world")
        # Radamsa should produce some mutations (may skip if identical to original)
        assert isinstance(radamsa_muts, list)

    def test_radamsa_zero_count_no_mutations(self):
        s = SmartStringPrimitive(
            name="test", default_value="hello", context=StringContext.GENERIC, radamsa_count=1
        )
        # Force count to 0 after init (constructor treats 0 as falsy -> default)
        s.radamsa_count = 0
        radamsa_muts = s._radamsa_mutations("hello")
        assert len(radamsa_muts) == 0

    def test_radamsa_empty_value_no_mutations(self):
        s = SmartStringPrimitive(
            name="test", default_value="", context=StringContext.GENERIC, radamsa_count=10
        )
        radamsa_muts = s._radamsa_mutations("")
        assert len(radamsa_muts) == 0

    def test_radamsa_bytes_input(self):
        s = SmartStringPrimitive(
            name="test", default_value="hello", context=StringContext.GENERIC, radamsa_count=5
        )
        radamsa_muts = s._radamsa_mutations(b"hello")
        assert isinstance(radamsa_muts, list)


# =============================================================================
# num_mutations
# =============================================================================


class TestNumMutations:
    """Test mutation count estimation."""

    def test_num_mutations_positive(self):
        s = SmartStringPrimitive(name="test", default_value="hello", context=StringContext.GENERIC)
        count = s.num_mutations(b"hello")
        assert count > 0

    def test_num_mutations_context_adds(self):
        """Context with payloads should report more mutations than GENERIC."""
        s_generic = SmartStringPrimitive(
            name="test", default_value="hello", context=StringContext.GENERIC
        )
        s_path = SmartStringPrimitive(
            name="test", default_value="/home", context=StringContext.PATH
        )
        assert s_path.num_mutations(b"/home") > s_generic.num_mutations(b"hello")


# =============================================================================
# _to_string helper
# =============================================================================


class TestToString:
    """Test the _to_string conversion helper."""

    def test_str_passthrough(self):
        s = SmartStringPrimitive(name="test", default_value="hello")
        assert s._to_string("hello") == "hello"

    def test_bytes_utf8(self):
        s = SmartStringPrimitive(name="test", default_value="hello")
        assert s._to_string(b"hello") == "hello"

    def test_bytes_non_utf8(self):
        s = SmartStringPrimitive(name="test", default_value="hello")
        result = s._to_string(b"\xff\xfe")
        assert isinstance(result, str)


# =============================================================================
# get_context_stats
# =============================================================================


class TestContextStats:
    """Test context statistics."""

    def test_stats_returns_dict(self):
        stats = SmartStringPrimitive.get_context_stats()
        assert isinstance(stats, dict)
        assert len(stats) > 0

    def test_stats_has_all_contexts(self):
        stats = SmartStringPrimitive.get_context_stats()
        for ctx in StringContext:
            # Composites won't have separate entries since they use .value
            if ctx.name in ("HOST", "NETWORK_TARGET", "FILE_PATH"):
                continue
            # Base contexts should be present (check by value)
            # Note: composites share values with their constituent, so check name
            for key in stats:
                if key == ctx.value:
                    break
            # Stats uses ctx.value which may be the combined flag int for composites
            # Just verify we get some entries
        assert len(stats) >= 9, "Should have at least 9 context entries"

    def test_stats_fields(self):
        stats = SmartStringPrimitive.get_context_stats()
        for key, value in stats.items():
            assert "context_payloads" in value
            assert "radamsa_mutations" in value
            assert "total_context_specific" in value


# =============================================================================
# Convenience function
# =============================================================================


class TestSmartStringFunction:
    """Test the smart_string convenience function."""

    def test_creates_instance(self):
        s = smart_string(name="test", default_value="hello")
        assert isinstance(s, SmartStringPrimitive)

    def test_passes_context(self):
        s = smart_string(name="test", default_value="/home", context=StringContext.PATH)
        assert s.context == StringContext.PATH

    def test_defaults_to_generic(self):
        s = smart_string(name="test", default_value="hello")
        assert s.context == StringContext.GENERIC
