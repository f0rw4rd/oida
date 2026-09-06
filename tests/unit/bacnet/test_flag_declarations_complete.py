"""Every flag read by a bacnet mixin must be declared in proto_args.py.

CODE_REVIEW.md HIGH bacnet/proto_args.py:115,199 noted 6 dispatcher-read
flags absent from the parser. Walk all mixins, collect every
getattr(self.args, "<dest>", ...) name, and assert each is either
declared as a parser argument or has a default in some mixin
__init__.
"""

import ast
import pathlib
import re
import unittest


BACNET_ROOT = pathlib.Path("src/oida/protocols/bacnet")


def _read(rel):
    return BACNET_ROOT.joinpath(rel).read_text()


def _declared_dests() -> set:
    """Parse proto_args.py for every dest argparse would create."""
    src = _read("proto_args.py")
    # Match "--some-flag" and dest="explicit_name" forms.
    dests = set()
    for m in re.finditer(r'add_argument\(\s*"(--[a-z][a-z0-9_-]*)"', src):
        dests.add(m.group(1).lstrip("-").replace("-", "_"))
    for m in re.finditer(r'dest="([a-z_][a-z0-9_]*)"', src):
        dests.add(m.group(1))
    return dests


def _consumed_dests() -> set:
    """Walk every mixin for getattr(self.args, "<name>", ...)."""
    dests = set()
    for f in (BACNET_ROOT / "mixins").rglob("*.py"):
        src = f.read_text()
        for m in re.finditer(
            r'getattr\(\s*self\.args\s*,\s*["\']([a-z_][a-z0-9_]*)["\']',
            src,
        ):
            dests.add(m.group(1))
    return dests


# Allow-list: framework-supplied attributes that come from BaseScanner /
# NetworkConnection / main parser, not from the bacnet parser.
_ALLOW = {
    "host",
    "rhost",
    "port",
    "rport",
    "timeout",
    "debug",
    "verbose",
    "read_only",
    "config",
    "interface",  # also in proto_args as SUPPRESS
    # --output and --format are declared on the MAIN parser (cli.py);
    # the contract test test_no_duplicate_output_verbose_flags asserts
    # protocols MUST NOT re-declare them. Shared Namespace makes them
    # visible to every mixin.
    "output",
    "format",
    # -q/--quiet is a global main-parser flag (like output/format); the SC
    # transport mixin reads it to suppress host-info printing.
    "quiet",
}


class TestEveryConsumedFlagIsDeclared(unittest.TestCase):
    def test_no_missing_dests(self):
        declared = _declared_dests()
        consumed = _consumed_dests()
        missing = (consumed - declared) - _ALLOW
        self.assertFalse(
            missing,
            "Bacnet mixins read these dests but proto_args doesn't declare "
            f"them — they will silently default to None:\n  {sorted(missing)}",
        )


if __name__ == "__main__":
    unittest.main()
