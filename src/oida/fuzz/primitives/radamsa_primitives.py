"""
Radamsa-powered fuzzing primitives

These primitives use radamsa-style mutations instead of boofuzz's
built-in mutation libraries. This provides:

1. Different mutation strategies
2. More exotic/creative mutations
3. Comparison between generative (boofuzz) and mutation (radamsa) approaches

Usage:
    # Instead of boofuzz String:
    String("Path", "/index.html", max_len=100)

    # Use RadamsaString:
    RadamsaString("Path", "/index.html", mutation_count=500)
"""

from boofuzz import helpers
from boofuzz.fuzzable import Fuzzable
from ..core.mutation import NativeRadamsaMutator, get_mutation_seed


class RadamsaString(Fuzzable):
    """
    String primitive that uses Radamsa for mutations

    Instead of boofuzz's 1,956 built-in string mutations, this uses
    Radamsa to generate creative mutations of the default value.

    Example:
        RadamsaString("Username", "admin", mutation_count=100)
    """

    def __init__(
        self, name=None, default_value="", mutation_count=100, encoding="utf-8", *args, **kwargs
    ):
        """
        Initialize RadamsaString

        Args:
            name: Field name for referencing
            default_value: Default string value to mutate
            mutation_count: Number of mutations to generate
            encoding: String encoding (default: utf-8)
        """
        # Convert to bytes for internal handling
        if isinstance(default_value, str):
            default_value = default_value.encode(encoding)
        else:
            default_value = helpers.str_to_bytes(default_value)

        super(RadamsaString, self).__init__(name=name, default_value=default_value, *args, **kwargs)

        self.mutation_count = mutation_count
        self.encoding = encoding
        self._mutator = NativeRadamsaMutator()

    def mutations(self, default_value):
        """
        Generate mutations using Radamsa

        Args:
            default_value: The default value to mutate

        Yields:
            Mutated values
        """
        for i in range(self.mutation_count):
            # Use global seed from CLI --seed for reproducibility
            base_seed = get_mutation_seed() or 0
            mutation_seed = base_seed + i
            mutated = self._mutator.mutate(default_value, seed=mutation_seed)
            yield mutated

    def encode(self, value, mutation_context):
        """Encode the value (pass-through for bytes)"""
        return value

    def num_mutations(self, default_value):
        """
        Return number of mutations this primitive will generate

        Args:
            default_value: The default value

        Returns:
            Number of mutations
        """
        return self.mutation_count


class RadamsaBytes(Fuzzable):
    """
    Bytes primitive that uses Radamsa for mutations

    Similar to RadamsaString but for binary data.

    Example:
        RadamsaBytes("BinaryData", b"\\x00\\x01\\x02\\x03", mutation_count=200)
    """

    def __init__(
        self, name=None, default_value=b"", mutation_count=100, max_len=None, *args, **kwargs
    ):
        """
        Initialize RadamsaBytes

        Args:
            name: Field name for referencing
            default_value: Default bytes value to mutate
            mutation_count: Number of mutations to generate
            max_len: Maximum length of mutated data (optional)
        """
        default_value = helpers.str_to_bytes(default_value)

        super(RadamsaBytes, self).__init__(name=name, default_value=default_value, *args, **kwargs)

        self.mutation_count = mutation_count
        self.max_len = max_len
        self._mutator = NativeRadamsaMutator()

    def mutations(self, default_value):
        """
        Generate mutations using Radamsa

        Args:
            default_value: The default value to mutate

        Yields:
            Mutated values
        """
        for i in range(self.mutation_count):
            # Use global seed from CLI --seed for reproducibility
            base_seed = get_mutation_seed() or 0
            mutation_seed = base_seed + i
            mutated = self._mutator.mutate(default_value, seed=mutation_seed)

            # Apply max_len if specified
            if self.max_len is not None and len(mutated) > self.max_len:
                mutated = mutated[: self.max_len]

            yield mutated

    def encode(self, value, mutation_context):
        """Encode the value (pass-through for bytes)"""
        return value

    def num_mutations(self, default_value):
        """Return number of mutations"""
        return self.mutation_count


class RadamsaBlock(Fuzzable):
    """
    Block primitive that uses Radamsa for mutations

    Mutates an entire block of data as a unit.
    Useful for fuzzing structured data where you want Radamsa
    to handle the entire structure rather than individual fields.

    Example:
        RadamsaBlock("HTTPRequest",
                     b"GET / HTTP/1.1\\r\\nHost: test\\r\\n\\r\\n",
                     mutation_count=1000)
    """

    def __init__(self, name=None, default_value=b"", mutation_count=100, *args, **kwargs):
        """
        Initialize RadamsaBlock

        Args:
            name: Block name for referencing
            default_value: Default block data to mutate
            mutation_count: Number of mutations to generate
        """
        default_value = helpers.str_to_bytes(default_value)

        super(RadamsaBlock, self).__init__(name=name, default_value=default_value, *args, **kwargs)

        self.mutation_count = mutation_count
        self._mutator = NativeRadamsaMutator()

    def mutations(self, default_value):
        """Generate mutations using Radamsa"""
        for i in range(self.mutation_count):
            # Use global seed from CLI --seed for reproducibility
            base_seed = get_mutation_seed() or 0
            mutation_seed = base_seed + i
            yield self._mutator.mutate(default_value, seed=mutation_seed)

    def encode(self, value, mutation_context):
        """Encode the value"""
        return value

    def num_mutations(self, default_value):
        """Return number of mutations"""
        return self.mutation_count
