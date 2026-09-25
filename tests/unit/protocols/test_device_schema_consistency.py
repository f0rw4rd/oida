"""Schema-consistency guard: listener data attrs must be declared fields.

Pcap listeners store per-protocol data on DiscoveredDevice instances via
``_ensure_device(data_attr="...")`` or direct assignment
(``device.foo_passive_data = {...}``). If the attr name is not a declared
dataclass field, ``DiscoveredDevice.merge_from()`` silently drops the data
on merge and ``build_device_description()`` never renders it.

This test scans the listener sources for such writes and fails when the
attr is not declared on DiscoveredDevice, so the two sets cannot drift
apart again.
"""

import ast
import re
from dataclasses import fields
from pathlib import Path

SRC_PCAP = Path(__file__).resolve().parents[3] / "src" / "oida" / "pcap"
SRC_DISCOVERY = Path(__file__).resolve().parents[3] / "src" / "oida" / "protocols" / "discovery"

_DATA_ATTR_RE = re.compile(r"^[a-z][a-z0-9_]*_data$")
# Attribute names that are protocol payloads on a device, not bookkeeping.
_ATTR_WHITELIST = set()

import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "src"))

from oida.protocols.discovery.core import DiscoveredDevice  # noqa: E402


def _declared_fields() -> set:
    return {f.name for f in fields(DiscoveredDevice)}


def _iter_listener_sources():
    yield from sorted(SRC_PCAP.glob("*.py"))


def _written_device_attrs(path: Path) -> set:
    """Attr names assigned to `something.foo_data = ...` in a listener module.

    Also picks up data_attr="foo_data" keyword arguments, which is how
    PySharkListenerBase._ensure_device() callers name the payload attr.
    Instances of local dataclasses (e.g. BGPCredential.auth_data) are
    filtered by only accepting names ending in `_data` that no local class
    declares as its own field.
    """
    tree = ast.parse(path.read_text(encoding="utf-8"))
    local_dataclass_fields = _local_dataclass_fields(tree)

    attrs = set()
    for node in ast.walk(tree):
        # device.foo_data = ...
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if (
                    isinstance(target, ast.Attribute)
                    and _DATA_ATTR_RE.match(target.attr)
                    and target.attr not in local_dataclass_fields
                ):
                    attrs.add(target.attr)
        # data_attr="foo_data"
        elif isinstance(node, ast.keyword) and node.arg == "data_attr":
            if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                attrs.add(node.value.value)
    return attrs - _ATTR_WHITELIST


def _local_dataclass_fields(tree: ast.Module) -> set:
    """Fields of @dataclass classes defined in this module (e.g. Credential
    dataclasses with an ``auth_data`` field) so their fields are not mistaken
    for device attrs."""
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef):
            is_dataclass = any(
                (isinstance(dec, ast.Name) and dec.id == "dataclass")
                or (isinstance(dec, ast.Attribute) and dec.attr == "dataclass")
                for dec in node.decorator_list
            )
            if not is_dataclass:
                continue
            for item in node.body:
                if isinstance(item, ast.AnnAssign) and isinstance(item.target, ast.Name):
                    names.add(item.target.id)
    return names


def test_listener_data_attrs_are_declared_on_device():
    declared = _declared_fields()
    offenders = {}
    for path in _iter_listener_sources():
        for attr in _written_device_attrs(path):
            if attr not in declared and attr not in _ATTR_WHITELIST:
                offenders.setdefault(attr, []).append(path.name)
    assert not offenders, (
        "Listeners write device data attrs that are NOT declared fields of "
        f"DiscoveredDevice - merge_from() drops them on merge: {offenders}. "
        "Declare each attr as `Optional[Dict[str, Any]] = None` on "
        "DiscoveredDevice."
    )


def test_data_attr_names_are_valid_identifiers():
    """Sanity on the extraction itself: we should find a substantial number
    of known-good attrs; guards against the AST walk silently matching
    nothing and the main test passing vacuously."""
    written = set()
    for path in _iter_listener_sources():
        written |= _written_device_attrs(path)
    assert len(written) >= 50, (
        f"AST scan found only {len(written)} attrs - extraction likely broken"
    )
    known_good = {"smb_passive_data", "tls_passive_data", "http_passive_data"}
    assert known_good <= written, f"Known attrs missing from scan: {known_good - written}"
