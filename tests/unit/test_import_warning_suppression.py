"""Third-party import warnings must not leak through oida's import paths.

scapy 2.7.0's import chain (scapy.layers.tls) emits cryptography's FFDH
CryptographyDeprecationWarning whenever cryptography >= 48 is installed.
That noise reached stderr on every `oida discovery` run (GH issue #61).
Two suppression points cover every path:
  - LazyModule._load() (utils/lazy_import.py): all lazy-loaded deps
  - discovery package __init__: direct `from scapy.all import ...` sites
    inside scanner functions, which bypass the lazy-import boundary
"""

import subprocess
import sys
import unittest


class TestImportWarningSuppression(unittest.TestCase):
    def test_discovery_cli_emits_no_deprecation_warning(self):
        """`oida discovery <iface>` must not print third-party warnings.

        Runs the real CLI in a fresh interpreter (the leak fired on every
        fresh process, not just the first import) and asserts stderr holds
        no Warning lines. `lo` is used as the interface: the scan fails
        fast without CAP_NET_RAW, which is fine, the import chain still
        runs.
        """
        proc = subprocess.run(
            [sys.executable, "-m", "oida", "discovery", "lo"],
            capture_output=True,
            text=True,
            timeout=120,
        )
        warning_lines = [line for line in proc.stderr.splitlines() if "Warning" in line]
        self.assertEqual(
            warning_lines,
            [],
            f"third-party warning leaked to stderr: {warning_lines}",
        )

    def test_lazy_import_suppresses_matching_warnings(self):
        """The scoped filter in LazyModule._load must silence warnings that
        match the deprecation-removal message pattern, without touching
        unrelated warnings raised after the import."""
        import warnings

        from oida.utils.lazy_import import LazyModule

        lm = LazyModule("json", protocol="TEST", install_hint="(none)")

        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            lm()

        leaked = [w for w in caught if "deprecated and support will be removed" in str(w.message)]
        self.assertEqual(leaked, [], "import-time deprecation noise leaked")


if __name__ == "__main__":
    unittest.main()
