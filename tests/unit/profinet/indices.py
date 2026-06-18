"""Mock of profinet.indices for unit tests.

The tests/unit/profinet/ package shadows the third-party ``profinet`` package,
so ``from profinet import indices`` resolves here instead.  This stub provides
the single function used by FuzzMixin._fuzz_writable_indices.
"""


def get_index_name(idx: int) -> str:
    """Return a human-readable name for a PROFINET index."""
    return f"Index_0x{idx:04X}"
