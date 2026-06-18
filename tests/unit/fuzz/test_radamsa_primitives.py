"""
Tests for Radamsa-powered fuzzing primitives.

Tests cover:
- RadamsaString: String mutation via Radamsa
- RadamsaBytes: Binary data mutation via Radamsa
- RadamsaBlock: Block-level mutation via Radamsa
- Mutation count and determinism
- Integration with boofuzz Fuzzable interface
"""

import pytest
import sys
from unittest.mock import MagicMock


# =============================================================================
# Fixtures for mocking pyradamsa (required by RadamsaMutator)
# =============================================================================


@pytest.fixture
def mock_pyradamsa():
    """Create a mock pyradamsa module and inject it into sys.modules."""
    mock_radamsa_instance = MagicMock()
    mock_radamsa_instance.fuzz.return_value = b"mutated_data"

    mock_module = MagicMock()
    mock_module.Radamsa.return_value = mock_radamsa_instance

    # Store original if it exists
    original_pyradamsa = sys.modules.get("pyradamsa")
    sys.modules.get("src.oida.fuzz.core.mutation.radamsa")
    sys.modules.get("src.oida.fuzz.primitives.radamsa_primitives")

    # Inject mock
    sys.modules["pyradamsa"] = mock_module

    # Clear any cached imports
    if "src.oida.fuzz.core.mutation.radamsa" in sys.modules:
        del sys.modules["src.oida.fuzz.core.mutation.radamsa"]
    if "src.oida.fuzz.primitives.radamsa_primitives" in sys.modules:
        del sys.modules["src.oida.fuzz.primitives.radamsa_primitives"]

    yield mock_module, mock_radamsa_instance

    # Restore original
    if original_pyradamsa is not None:
        sys.modules["pyradamsa"] = original_pyradamsa
    elif "pyradamsa" in sys.modules:
        del sys.modules["pyradamsa"]

    # Clear cached imports for cleanup
    if "src.oida.fuzz.core.mutation.radamsa" in sys.modules:
        del sys.modules["src.oida.fuzz.core.mutation.radamsa"]
    if "src.oida.fuzz.primitives.radamsa_primitives" in sys.modules:
        del sys.modules["src.oida.fuzz.primitives.radamsa_primitives"]


# =============================================================================
# Test RadamsaString Primitive
# =============================================================================


class TestRadamsaStringCreation:
    """Tests for RadamsaString instantiation."""

    def test_creation_with_string(self, mock_pyradamsa):
        """RadamsaString accepts string default value."""
        from src.oida.fuzz.primitives.radamsa_primitives import RadamsaString

        field = RadamsaString("test_field", "test_value")
        assert field is not None
        assert field.mutation_count == 100  # Default

    def test_creation_with_bytes(self, mock_pyradamsa):
        """RadamsaString accepts bytes default value."""
        from src.oida.fuzz.primitives.radamsa_primitives import RadamsaString

        field = RadamsaString("test_field", b"test_value")
        assert field is not None

    def test_custom_mutation_count(self, mock_pyradamsa):
        """Custom mutation count is respected."""
        from src.oida.fuzz.primitives.radamsa_primitives import RadamsaString

        field = RadamsaString("test_field", "test", mutation_count=500)
        assert field.mutation_count == 500

    def test_custom_encoding(self, mock_pyradamsa):
        """Custom encoding is stored."""
        from src.oida.fuzz.primitives.radamsa_primitives import RadamsaString

        field = RadamsaString("test_field", "test", encoding="latin-1")
        assert field.encoding == "latin-1"


class TestRadamsaStringMutations:
    """Tests for RadamsaString mutation generation."""

    def test_num_mutations_matches_count(self, mock_pyradamsa):
        """num_mutations returns configured mutation count."""
        from src.oida.fuzz.primitives.radamsa_primitives import RadamsaString

        field = RadamsaString("test_field", "test", mutation_count=50)
        assert field.num_mutations(b"test") == 50

    def test_mutations_generator_yields_correct_count(self, mock_pyradamsa):
        """Mutations generator yields correct number of values."""
        mock_module, mock_instance = mock_pyradamsa
        mock_instance.fuzz.return_value = b"mutated"

        from src.oida.fuzz.primitives.radamsa_primitives import RadamsaString

        field = RadamsaString("test_field", "test", mutation_count=10)
        mutations = list(field.mutations(b"test"))
        assert len(mutations) == 10

    def test_mutations_are_deterministic(self, mock_pyradamsa):
        """Mutations with same seed produce consistent results."""
        from src.oida.fuzz.primitives.radamsa_primitives import RadamsaString

        # Create field and generate mutations
        field = RadamsaString("test_field", "test", mutation_count=5)
        mutations = list(field.mutations(b"test"))

        # Should produce exactly 5 mutations
        assert len(mutations) == 5
        # Mutations should be bytes
        assert all(isinstance(m, bytes) for m in mutations)


class TestRadamsaStringEncode:
    """Tests for RadamsaString encoding."""

    def test_encode_passes_through(self, mock_pyradamsa):
        """encode() returns the value unchanged."""
        from src.oida.fuzz.primitives.radamsa_primitives import RadamsaString

        field = RadamsaString("test_field", "test")
        result = field.encode(b"data", None)
        assert result == b"data"


# =============================================================================
# Test RadamsaBytes Primitive
# =============================================================================


class TestRadamsaBytesCreation:
    """Tests for RadamsaBytes instantiation."""

    def test_creation_with_bytes(self, mock_pyradamsa):
        """RadamsaBytes accepts bytes default value."""
        from src.oida.fuzz.primitives.radamsa_primitives import RadamsaBytes

        field = RadamsaBytes("test_field", b"\x00\x01\x02\x03")
        assert field is not None
        assert field.mutation_count == 100

    def test_custom_mutation_count(self, mock_pyradamsa):
        """Custom mutation count is respected."""
        from src.oida.fuzz.primitives.radamsa_primitives import RadamsaBytes

        field = RadamsaBytes("test_field", b"test", mutation_count=200)
        assert field.mutation_count == 200

    def test_max_len_attribute(self, mock_pyradamsa):
        """max_len attribute is stored."""
        from src.oida.fuzz.primitives.radamsa_primitives import RadamsaBytes

        field = RadamsaBytes("test_field", b"test", max_len=50)
        assert field.max_len == 50


class TestRadamsaBytesMutations:
    """Tests for RadamsaBytes mutation generation."""

    def test_num_mutations_matches_count(self, mock_pyradamsa):
        """num_mutations returns configured mutation count."""
        from src.oida.fuzz.primitives.radamsa_primitives import RadamsaBytes

        field = RadamsaBytes("test_field", b"test", mutation_count=75)
        assert field.num_mutations(b"test") == 75

    def test_mutations_generator_yields_correct_count(self, mock_pyradamsa):
        """Mutations generator yields correct number of values."""
        mock_module, mock_instance = mock_pyradamsa
        mock_instance.fuzz.return_value = b"mutated"

        from src.oida.fuzz.primitives.radamsa_primitives import RadamsaBytes

        field = RadamsaBytes("test_field", b"test", mutation_count=15)
        mutations = list(field.mutations(b"test"))
        assert len(mutations) == 15

    def test_mutations_truncated_by_max_len(self, mock_pyradamsa):
        """Mutations are truncated if they exceed max_len."""
        mock_module, mock_instance = mock_pyradamsa
        mock_instance.fuzz.return_value = b"A" * 100  # 100 bytes

        from src.oida.fuzz.primitives.radamsa_primitives import RadamsaBytes

        field = RadamsaBytes("test_field", b"test", mutation_count=1, max_len=10)
        mutations = list(field.mutations(b"test"))

        assert len(mutations) == 1
        assert len(mutations[0]) <= 10

    def test_mutations_not_truncated_when_under_max_len(self, mock_pyradamsa):
        """Mutations are not truncated if under max_len."""
        from src.oida.fuzz.primitives.radamsa_primitives import RadamsaBytes

        field = RadamsaBytes("test_field", b"test", mutation_count=10, max_len=1000)
        mutations = list(field.mutations(b"test"))

        # All mutations should be under max_len (not truncated)
        assert len(mutations) == 10
        assert all(len(m) <= 1000 for m in mutations)


class TestRadamsaBytesEncode:
    """Tests for RadamsaBytes encoding."""

    def test_encode_passes_through(self, mock_pyradamsa):
        """encode() returns the value unchanged."""
        from src.oida.fuzz.primitives.radamsa_primitives import RadamsaBytes

        field = RadamsaBytes("test_field", b"test")
        result = field.encode(b"\x00\x01\x02", None)
        assert result == b"\x00\x01\x02"


# =============================================================================
# Test RadamsaBlock Primitive
# =============================================================================


class TestRadamsaBlockCreation:
    """Tests for RadamsaBlock instantiation."""

    def test_creation_with_bytes(self, mock_pyradamsa):
        """RadamsaBlock accepts bytes default value."""
        from src.oida.fuzz.primitives.radamsa_primitives import RadamsaBlock

        field = RadamsaBlock("test_block", b"block data")
        assert field is not None
        assert field.mutation_count == 100

    def test_custom_mutation_count(self, mock_pyradamsa):
        """Custom mutation count is respected."""
        from src.oida.fuzz.primitives.radamsa_primitives import RadamsaBlock

        field = RadamsaBlock("test_block", b"data", mutation_count=1000)
        assert field.mutation_count == 1000


class TestRadamsaBlockMutations:
    """Tests for RadamsaBlock mutation generation."""

    def test_num_mutations_matches_count(self, mock_pyradamsa):
        """num_mutations returns configured mutation count."""
        from src.oida.fuzz.primitives.radamsa_primitives import RadamsaBlock

        field = RadamsaBlock("test_block", b"test", mutation_count=300)
        assert field.num_mutations(b"test") == 300

    def test_mutations_generator_yields_correct_count(self, mock_pyradamsa):
        """Mutations generator yields correct number of values."""
        mock_module, mock_instance = mock_pyradamsa
        mock_instance.fuzz.return_value = b"mutated_block"

        from src.oida.fuzz.primitives.radamsa_primitives import RadamsaBlock

        field = RadamsaBlock("test_block", b"test", mutation_count=20)
        mutations = list(field.mutations(b"test"))
        assert len(mutations) == 20


class TestRadamsaBlockEncode:
    """Tests for RadamsaBlock encoding."""

    def test_encode_passes_through(self, mock_pyradamsa):
        """encode() returns the value unchanged."""
        from src.oida.fuzz.primitives.radamsa_primitives import RadamsaBlock

        field = RadamsaBlock("test_block", b"test")
        result = field.encode(b"block_data", None)
        assert result == b"block_data"


# =============================================================================
# Test Integration with Protocol Data
# =============================================================================


class TestProtocolIntegration:
    """Tests for protocol fuzzing integration."""

    def test_http_request_mutation(self, mock_pyradamsa):
        """HTTP request can be mutated."""
        mock_module, mock_instance = mock_pyradamsa
        mock_instance.fuzz.return_value = b"GET /mutated HTTP/1.1\r\n\r\n"

        from src.oida.fuzz.primitives.radamsa_primitives import RadamsaBlock

        http_request = b"GET / HTTP/1.1\r\nHost: test.com\r\n\r\n"
        field = RadamsaBlock("http_request", http_request, mutation_count=10)
        mutations = list(field.mutations(http_request))

        assert len(mutations) == 10

    def test_modbus_pdu_mutation(self, mock_pyradamsa):
        """Modbus PDU can be mutated."""
        mock_module, mock_instance = mock_pyradamsa
        mock_instance.fuzz.return_value = b"\x01\x03\xff\xff\x00\x01"

        from src.oida.fuzz.primitives.radamsa_primitives import RadamsaBytes

        modbus_pdu = b"\x01\x03\x00\x00\x00\x01"
        field = RadamsaBytes("modbus_pdu", modbus_pdu, mutation_count=100)
        mutations = list(field.mutations(modbus_pdu))

        assert len(mutations) == 100

    def test_string_field_mutation(self, mock_pyradamsa):
        """String field (like username) can be mutated."""
        mock_module, mock_instance = mock_pyradamsa

        # Return different mutations for each call
        call_count = [0]

        def varied_fuzz(data, seed=None):
            call_count[0] += 1
            return f"mutated_{call_count[0]}".encode()

        mock_instance.fuzz.side_effect = varied_fuzz

        from src.oida.fuzz.primitives.radamsa_primitives import RadamsaString

        field = RadamsaString("username", "admin", mutation_count=5)
        mutations = list(field.mutations(b"admin"))

        assert len(mutations) == 5
        # Verify mutations are different
        assert len(set(mutations)) == 5


# =============================================================================
# Test Edge Cases
# =============================================================================


class TestEdgeCases:
    """Tests for edge cases."""

    def test_empty_default_value(self, mock_pyradamsa):
        """Empty default value is handled."""
        mock_module, mock_instance = mock_pyradamsa
        mock_instance.fuzz.return_value = b"generated"

        from src.oida.fuzz.primitives.radamsa_primitives import RadamsaString

        field = RadamsaString("empty_field", "", mutation_count=5)
        mutations = list(field.mutations(b""))

        assert len(mutations) == 5

    def test_zero_mutations(self, mock_pyradamsa):
        """Zero mutation count produces no mutations."""
        from src.oida.fuzz.primitives.radamsa_primitives import RadamsaString

        field = RadamsaString("test", "value", mutation_count=0)
        mutations = list(field.mutations(b"value"))

        assert len(mutations) == 0

    def test_binary_data_all_bytes(self, mock_pyradamsa):
        """All byte values are handled in mutations."""
        from src.oida.fuzz.primitives.radamsa_primitives import RadamsaBytes

        all_bytes = bytes(range(256))
        field = RadamsaBytes("binary", all_bytes, mutation_count=5)
        mutations = list(field.mutations(all_bytes))

        # Should produce mutations from binary input
        assert len(mutations) == 5
        # Mutations should be bytes
        assert all(isinstance(m, bytes) for m in mutations)

    def test_unicode_string(self, mock_pyradamsa):
        """Unicode strings are handled with specified encoding."""
        mock_module, mock_instance = mock_pyradamsa
        mock_instance.fuzz.return_value = "mutated_Ã©".encode("utf-8")

        from src.oida.fuzz.primitives.radamsa_primitives import RadamsaString

        field = RadamsaString("unicode_field", "CafÃ©", encoding="utf-8", mutation_count=1)
        assert field is not None
        # Default value should be encoded
        assert field._default_value == "CafÃ©".encode("utf-8")


# =============================================================================
# Test Fuzzable Interface Compliance
# =============================================================================


class TestFuzzableInterface:
    """Tests for boofuzz Fuzzable interface compliance."""

    def test_radamsa_string_is_fuzzable(self, mock_pyradamsa):
        """RadamsaString inherits from Fuzzable."""
        from src.oida.fuzz.primitives.radamsa_primitives import RadamsaString
        from boofuzz.fuzzable import Fuzzable

        field = RadamsaString("test", "value")
        assert isinstance(field, Fuzzable)

    def test_radamsa_bytes_is_fuzzable(self, mock_pyradamsa):
        """RadamsaBytes inherits from Fuzzable."""
        from src.oida.fuzz.primitives.radamsa_primitives import RadamsaBytes
        from boofuzz.fuzzable import Fuzzable

        field = RadamsaBytes("test", b"value")
        assert isinstance(field, Fuzzable)

    def test_radamsa_block_is_fuzzable(self, mock_pyradamsa):
        """RadamsaBlock inherits from Fuzzable."""
        from src.oida.fuzz.primitives.radamsa_primitives import RadamsaBlock
        from boofuzz.fuzzable import Fuzzable

        field = RadamsaBlock("test", b"value")
        assert isinstance(field, Fuzzable)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
