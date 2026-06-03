"""CODESYS V3 PLC discovery exists and exposes a contract.

§1.1 audit item: 'CODESYS gateway discovery'. The CODESYSScanner class
in src/oida/protocols/discovery/ics.py wraps the proprietary UDP
service-discovery protocol; verify it has the expected shape so a
future refactor doesn't accidentally drop the discoverer.
"""

import unittest


class TestCODESYSScannerContract(unittest.TestCase):
    def test_class_exists(self):
        from oida.protocols.discovery.ics import CODESYSScanner

        self.assertTrue(callable(CODESYSScanner))

    def test_class_takes_expected_init_params(self):
        import inspect

        from oida.protocols.discovery.ics import CODESYSScanner

        sig = inspect.signature(CODESYSScanner.__init__)
        params = sig.parameters
        # Interface is required (positional or keyword); subnet + timeout
        # are documented kwargs.
        self.assertIn("interface", params)
        self.assertIn("subnet", params)
        self.assertIn("timeout", params)

    def test_scan_method_present(self):
        from oida.protocols.discovery.ics import CODESYSScanner

        self.assertTrue(hasattr(CODESYSScanner, "scan"))
        self.assertTrue(callable(CODESYSScanner.scan))

    def test_proto_args_advertises_codesys(self):
        """--enable-modules must include 'codesys' so operators can run it."""
        import pathlib

        src = pathlib.Path("src/oida/protocols/discovery/proto_args.py").read_text()
        self.assertIn('("codesys"', src)


if __name__ == "__main__":
    unittest.main()
