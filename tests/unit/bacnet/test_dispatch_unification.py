"""BAC0/bacpypes3 unification: bacpypes3 is the default path.

CODE_REVIEW.md HIGH bacnet/nxc_connection.py:111-117. The old dispatch
heuristic misrouted public 172.0.0.0/8 hosts to the BAC0 broadcast
path. The fix unifies on bacpypes3 unless the operator explicitly
opts back into BAC0 via --use-bac0.
"""

import pathlib
import unittest


def _read(rel):
    return pathlib.Path(rel).read_text()


class TestDispatchUnification(unittest.TestCase):
    def test_default_path_is_bacpypes3(self):
        src = _read("src/oida/protocols/bacnet/nxc_connection.py")
        # The patched proto_flow checks use_bac0 flag, with bacpypes3
        # as the default (else branch).
        self.assertIn("use_bac0 = (", src)
        self.assertIn('getattr(self.args, "use_bac0", False)', src)
        # The else branch dispatches _raw_scan (bacpypes3).
        # Find the dispatch block and verify default is _raw_scan.
        idx = src.find("use_bac0 = (")
        end = src.find("def ", idx + 1)
        block = src[idx:end] if end > 0 else src[idx:]
        self.assertIn("self._raw_scan()", block)
        # And BAC0 path is the gated branch.
        self.assertIn("_async_proto_flow()", block)

    def test_no_more_172_prefix_check(self):
        """The buggy 172.0.0.0/8 startswith heuristic must be gone."""
        src = _read("src/oida/protocols/bacnet/nxc_connection.py")
        # Old buggy patterns
        self.assertNotIn('local_prefixes = ("192.168.", "10.", "172.")', src)
        self.assertNotIn('any(self.host.startswith(p) for p in local_prefixes)', src)

    def test_use_bac0_flag_declared(self):
        src = _read("src/oida/protocols/bacnet/proto_args.py")
        self.assertIn('"--use-bac0"', src)


if __name__ == "__main__":
    unittest.main()
