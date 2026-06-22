"""load_register_map must reject non-JSON direct paths and traversal.

CODE_REVIEW.md HIGH: arbitrary file read via --register-map.
"""

import json
import tempfile
import unittest
from pathlib import Path


class TestRegisterMapTraversal(unittest.TestCase):
    def test_non_json_direct_path_rejected(self):
        from oida.protocols.modbus.decoder import load_register_map

        with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as f:
            f.write(b"not json")
            txt_path = f.name

        with self.assertRaises(ValueError) as cm:
            load_register_map(txt_path)
        self.assertIn(".json", str(cm.exception))

    def test_json_direct_path_loads(self):
        from oida.protocols.modbus.decoder import load_register_map

        with tempfile.NamedTemporaryFile(suffix=".json", mode="w", delete=False) as f:
            json.dump({"registers": {}, "model_id": 1}, f)
            json_path = f.name

        result = load_register_map(json_path)
        self.assertIsNotNone(result)
        self.assertEqual(result["model_id"], 1)

    def test_traversal_in_search_name_does_not_escape(self):
        from oida.protocols.modbus.decoder import load_register_map

        # A traversal name that does not resolve to an existing file must
        # not escape the search root: the _resolve_inside guard keeps the
        # candidate inside register_maps/, so the lookup returns None
        # rather than reading a file outside the root.
        result = load_register_map("../../nonexistent-xyzzy/passwd")
        self.assertIsNone(result)


if __name__ == "__main__":
    unittest.main()
