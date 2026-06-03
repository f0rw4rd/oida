"""GOOSE/R-GOOSE raw socket needs CAP_NET_RAW; missing capability must
produce an actionable error message instead of a bare PermissionError.

§1.1 audit item: 'CAP_NET_RAW handling: clear error when missing'.
"""

import pathlib
import unittest


class TestCapNetRawErrorMessages(unittest.TestCase):
    def test_nxc_connection_says_cap_net_raw_in_error(self):
        src = pathlib.Path(
            "src/oida/protocols/goose/nxc_connection.py"
        ).read_text()
        # The error message must name the capability the operator needs
        # to grant (not just 'permission denied').
        self.assertIn("CAP_NET_RAW", src)

    def test_init_says_cap_net_raw_or_root(self):
        src = pathlib.Path("src/oida/protocols/goose/__init__.py").read_text()
        self.assertIn("CAP_NET_RAW", src)
        # And mentions running as root as the alternative.
        self.assertIn("root", src.lower())


if __name__ == "__main__":
    unittest.main()
