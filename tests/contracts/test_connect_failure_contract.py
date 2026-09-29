"""Fleet-wide connect-failure contract (GH issue #59).

Every registered protocol runner must route connect failures through
``connection.record_connect_failure()`` so console output (exactly one
``Connect failed: <cause> (<target>)`` line) and the JSON contract
(``results["error"] == "connect <cause>..."``, ``success=False``) stay
uniform across the whole CLI.

The original GH #59 fix adopted the contract in 4 of 21 runners and its
test file only covered those 4 -- a partial adoption that shipped looking
complete. This suite is the mechanical prevention: it walks EVERY protocol
the loader can register, loads the actual runner module, and requires the
adoption (or an explicit, documented exemption). A new protocol, or an
old one that regresses, fails CI here regardless of whether anyone wrote
a behavior test for it.
"""

from __future__ import annotations

import ast
import importlib
import re
import unittest
from pathlib import Path

from oida.loader import ProtocolLoader

PROTOCOLS_DIR = Path(__file__).resolve().parents[2] / "src" / "oida" / "protocols"

# Marker a module carries to be exempt from the contract. Must sit next to
# the exemption reason, e.g.:
#     # connect-failure: exempt (serial bus - no network connect stage)
EXEMPT_RE = re.compile(r"#\s*connect-failure:\s*exempt[^\n]*")

# Non-transport protocols: pure passive capture / local generation.
# They have no connect stage by design, and several import heavy deps
# only at runtime. Listed explicitly (not discovered) because the loader
# registers them like any other protocol.
EXEMPT_PROTOCOLS = {
    "pcap": "passive listener pipeline - no outbound connect",
    "discovery": "multi-protocol discovery - no single connect stage",
}


def _runner_source(protocol_name: str) -> tuple[str, str]:
    """Return (module_name, source_text) of the runner module for a protocol.

    Resolves the same module the loader dispatches to: the package's
    __init__.py when the protocol is a package with the class in it, else
    cli_runner.py, else the single .py file.
    """
    pkg_dir = PROTOCOLS_DIR / protocol_name
    if pkg_dir.is_dir():
        for candidate in ("cli_runner.py", "__init__.py"):
            path = pkg_dir / candidate
            if path.exists():
                return (
                    f"oida.protocols.{protocol_name}.{candidate[:-3]}",
                    path.read_text(encoding="utf-8"),
                )
        raise AssertionError(f"{protocol_name}: no cli_runner.py or __init__.py")
    single = PROTOCOLS_DIR / f"{protocol_name}.py"
    if single.exists():
        return (f"oida.protocols.{protocol_name}", single.read_text(encoding="utf-8"))
    raise AssertionError(f"{protocol_name}: no runner module found")


def _protocol_names() -> list[str]:
    loader = ProtocolLoader(str(PROTOCOLS_DIR))
    return sorted(loader.get_protocols().keys())


def _has_exemption_reason(source: str) -> bool:
    """An exemption is only valid with a written reason after the marker."""
    m = EXEMPT_RE.search(source)
    return bool(m and m.group(0).strip() != "# connect-failure: exempt")


class TestFleetWideConnectFailureContract(unittest.TestCase):
    """Every registered runner adopts record_connect_failure() or is exempt."""

    def test_every_runner_calls_record_connect_failure(self):
        missing = []
        for name in _protocol_names():
            if name in EXEMPT_PROTOCOLS:
                continue
            module_name, source = _runner_source(name)
            if EXEMPT_RE.search(source):
                # Documented in-module exemption (with reason) - allowed.
                continue
            if "record_connect_failure" not in source:
                missing.append(module_name)
        self.assertEqual(
            missing,
            [],
            "Protocol runners without the GH #59 connect-failure contract "
            "(add record_connect_failure() on the failure path, or a "
            "'# connect-failure: exempt (<reason>)' marker): " + ", ".join(missing),
        )

    def test_exempt_protocols_actually_exist(self):
        names = set(_protocol_names())
        stale = sorted(set(EXEMPT_PROTOCOLS) - names)
        self.assertEqual(stale, [], f"exemptions for nonexistent protocols: {stale}")

    def test_runner_source_parses(self):
        """The adoption check greps source; guard against unreadable files."""
        broken = []
        for name in _protocol_names():
            if name in EXEMPT_PROTOCOLS:
                continue
            module_name, source = _runner_source(name)
            try:
                ast.parse(source)
            except SyntaxError as e:
                broken.append(f"{module_name}: does not parse: {e}")
        self.assertEqual(broken, [], "runner sources that do not parse")


class TestAdoptedRunnersImportable(unittest.TestCase):
    """Smoke-import each adopting runner so the contract is not just textual.

    A module that greps for record_connect_failure but cannot be imported
    (e.g. a broken import added in the same edit) would otherwise pass the
    source check. Importing the runner module, without instantiating the
    class, catches that.
    """

    @unittest.skipUnless(
        Path(PROTOCOLS_DIR).exists(),
        "protocol sources not on disk (frozen install)",
    )
    def test_runner_modules_import(self):
        errors = []
        for name in _protocol_names():
            if name in EXEMPT_PROTOCOLS:
                continue
            module_name, _ = _runner_source(name)
            try:
                importlib.import_module(module_name)
            except Exception as e:  # noqa: BLE001 - collect, report all
                errors.append(f"{module_name}: {e!r}")
        self.assertEqual(errors, [], "runner modules that fail to import: " + "; ".join(errors))


if __name__ == "__main__":
    unittest.main()
