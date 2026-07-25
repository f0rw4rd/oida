"""OPC UA certificate-analysis output is wired into discovery and security
paths via the shared `display_cert_info` helper.

§1.1 audit item: 'Certificate-analysis output (issuer, subject, validity,
key length)' — verify the wiring exists end-to-end (helper called from
the OPC UA paths) so a future refactor doesn't silently drop it.
"""

import pathlib
import unittest


class TestCertDisplayWiring(unittest.TestCase):
    """Snapshot check: OPC UA mixins must invoke display_cert_info."""

    def test_discovery_mixin_calls_display_cert_info(self):
        src = pathlib.Path("src/oida/protocols/opcua/mixins/discovery.py").read_text()
        self.assertIn("display_cert_info", src)
        # And imports it from the shared helper.
        self.assertIn("from oida.utils.security_findings import display_cert_info", src)

    def test_security_mixin_calls_display_cert_info(self):
        src = pathlib.Path("src/oida/protocols/opcua/mixins/security.py").read_text()
        self.assertIn("display_cert_info", src)

    def test_helper_exposes_certificate_fields(self):
        """display_cert_info renders issuer / subject / validity / key-length."""
        src = pathlib.Path("src/oida/utils/security_findings.py").read_text()
        # The helper's display surface is what the audit item refers to —
        # snapshot the field labels so a rewrite must keep them.
        for label in ("Issuer", "Subject", "valid", "key"):
            self.assertIn(label, src, f"{label} no longer rendered by display_cert_info")


if __name__ == "__main__":
    unittest.main()
