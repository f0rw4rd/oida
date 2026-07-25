"""OPC UA credential testing must actually validate, not just set_user().

asyncua.Client.set_user() is a sync setter that configures the next
outgoing request — it does NOT validate credentials. The old code
reported every credential as VALID because set_user() never raised.
CODE_REVIEW.md HIGH ('every credential silently valid').
"""

import unittest


class TestCredentialActuallyVerified(unittest.TestCase):
    """The patched _test_credentials_list must use a probe connection."""

    def test_source_uses_probe_client_connect(self):
        """Belt-and-braces: the fix probes with connect()+read."""
        import pathlib

        src = pathlib.Path("src/oida/protocols/opcua/scanner.py").read_text()
        # Must call connect() on the probe client (not just set_user).
        self.assertIn("await probe_client.connect()", src)
        # Must exercise an authenticated read to confirm session.
        self.assertIn("read_browse_name", src)
        # Must disconnect cleanly.
        self.assertIn("probe_client.disconnect()", src)

    def test_invalid_credential_recorded_as_error_not_valid(self):
        """If connect raises, the credential must not be reported VALID."""
        import pathlib

        src = pathlib.Path("src/oida/protocols/opcua/scanner.py").read_text()
        # The error branch records 'error' status, not 'valid'.
        self.assertIn('results["username_password"][username] = "error"', src)

    def test_valid_credential_recorded_only_after_read(self):
        """Belt-and-braces: 'valid' assignment must follow read_browse_name."""
        import pathlib

        src = pathlib.Path("src/oida/protocols/opcua/scanner.py").read_text()
        valid_idx = src.find('results["username_password"][username] = "valid"')
        read_idx = src.find("await probe_client.get_root_node().read_browse_name()")
        self.assertGreater(valid_idx, 0)
        self.assertGreater(read_idx, 0)
        self.assertLess(read_idx, valid_idx, "'valid' must come AFTER read probe")


if __name__ == "__main__":
    unittest.main()
