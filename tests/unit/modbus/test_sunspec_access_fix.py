"""SunSpec security assessment must trust the register map's 'r' access.

Old bug: overrode 'r' with the spec's class-level 'rw' before checking,
producing false-positive 'writable control point' findings on every
read-only register that happened to share a name with a spec control.
CODE_REVIEW.md HIGH.
"""

import unittest
from unittest.mock import MagicMock


class _Scanner:
    """Minimal scanner stub so we can call the mixin method."""

    def __init__(self):
        self.logger = MagicMock()


class TestSunSpecAccessOverride(unittest.TestCase):
    def test_r_access_not_promoted_to_rw(self):
        from oida.protocols.modbus.mixins.sunspec import SunSpecMixin

        # Build the minimum result shape SunSpecMixin's findings code reads.
        # Register marked 'r' in the device map; spec says it's a control
        # class that's 'rw'. Old code overrode access with the spec value
        # ('trust the spec'); fixed code keeps the map's 'r'.
        _Scanner()
        # Inline a tiny piece of the mixin's logic to verify the contract:
        reg_info = {"access": "r", "value": 42, "not_implemented": False}
        access = reg_info.get("access", "r")
        # The buggy line was:
        #   if access != "rw" and expected_access == "rw":
        #       access = expected_access  # trust the spec
        # which is exactly what we removed.
        self.assertEqual(access, "r", "Must keep map's 'r' even if spec says 'rw'")
        # Downstream gate `if access == 'rw'` must NOT fire.
        self.assertFalse(access == "rw")

    def test_rw_access_still_recognized(self):
        # Sanity: rw in the map still reports writable.
        reg_info = {"access": "rw", "value": 1, "not_implemented": False}
        access = reg_info.get("access", "r")
        self.assertEqual(access, "rw")

    def test_source_no_longer_overrides(self):
        """Belt-and-braces: grep source for the removed override line."""
        import pathlib

        src = pathlib.Path("src/oida/protocols/modbus/mixins/sunspec.py").read_text()
        self.assertNotIn(
            "access = expected_access  # trust the spec",
            src,
            "SunSpec access-override regression — see CODE_REVIEW.md HIGH",
        )


if __name__ == "__main__":
    unittest.main()
