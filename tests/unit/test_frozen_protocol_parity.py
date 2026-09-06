"""Frozen-build protocol list must match the filesystem-discovered set.

Normal runs discover protocols by scanning ``src/oida/protocols/``. Frozen
(PyInstaller) builds cannot scan the filesystem, so they iterate
``loader._KNOWN_PROTOCOLS`` instead, which is derived from
``PROTOCOL_DEPENDENCIES``. If a protocol is added without a deps entry it
works from source but silently disappears from the shipped binary. This
test makes that drift a CI failure instead of a release surprise.
"""

import unittest
from pathlib import Path

from oida.loader import ProtocolLoader, _KNOWN_PROTOCOLS

PROTOCOLS_DIR = Path(__file__).resolve().parents[2] / "src" / "oida" / "protocols"


class TestFrozenProtocolParity(unittest.TestCase):
    def test_known_list_matches_filesystem_discovery(self):
        loaded = set(ProtocolLoader(str(PROTOCOLS_DIR)).get_protocols())
        known = set(_KNOWN_PROTOCOLS)

        missing_from_frozen = sorted(loaded - known)
        stale_in_frozen = sorted(known - loaded)

        self.assertEqual(
            missing_from_frozen,
            [],
            "Protocols discovered on disk but absent from PROTOCOL_DEPENDENCIES "
            "(invisible in frozen/PyInstaller builds): "
            f"{missing_from_frozen}. Add them to PROTOCOL_DEPENDENCIES.",
        )
        self.assertEqual(
            stale_in_frozen,
            [],
            "Protocols in PROTOCOL_DEPENDENCIES with no module on disk "
            f"(stale frozen-build entries): {stale_in_frozen}.",
        )


if __name__ == "__main__":
    unittest.main()
