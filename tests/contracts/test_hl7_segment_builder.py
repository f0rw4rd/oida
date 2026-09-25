"""Contract: every `segment_builder.build_*` call site in HL7 mixins must
resolve to a real method on HL7SegmentBuilder.

The class-of-bug: a mixin calls `self.segment_builder.build_xyz(...)` for a
segment that never had a builder implemented. AttributeError gets caught by
the outer try/except in the caller and the function silently falls back to
generic test messages — caller thinks it sent BAR^P01 with full GT1/IN1/FT1
segments, server actually got a stub.

master_file.py + financial.py both shipped this way.
"""

from __future__ import annotations

import ast
import pathlib

from tests._ast_safe import safe_parse

HL7_ROOT = pathlib.Path(__file__).resolve().parents[2] / "src" / "oida" / "protocols" / "hl7"


def _builder_methods() -> set[str]:
    """Collect every `def build_<x>` defined on HL7SegmentBuilder."""
    tree = safe_parse((HL7_ROOT / "segments.py").read_text())
    out: set[str] = set()
    for cls in ast.walk(tree):
        if isinstance(cls, ast.ClassDef) and cls.name == "HL7SegmentBuilder":
            for node in cls.body:
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    if node.name.startswith("build_"):
                        out.add(node.name)
    return out


def _builder_call_sites() -> set[tuple[str, str]]:
    """Find every `*.segment_builder.build_<x>(...)` call. Returns (file, method)."""
    out: set[tuple[str, str]] = set()
    for py in HL7_ROOT.rglob("*.py"):
        if py.name == "segments.py":
            continue
        try:
            tree = safe_parse(py.read_text())
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            f = node.func
            if not isinstance(f, ast.Attribute):
                continue
            if not f.attr.startswith("build_"):
                continue
            # Match `<something>.segment_builder.build_x`
            if isinstance(f.value, ast.Attribute) and f.value.attr == "segment_builder":
                out.add((str(py.relative_to(HL7_ROOT)), f.attr))
    return out


def test_every_segment_builder_call_resolves():
    """No silent fallbacks: every build_X call must map to a real method."""
    defined = _builder_methods()
    called = _builder_call_sites()
    missing = {(f, m) for (f, m) in called if m not in defined}
    assert not missing, (
        "HL7 mixins call segment_builder methods that don't exist — caller will "
        "silently fall back to generic test messages. Either implement the method "
        "in segments.py:HL7SegmentBuilder or stop calling it.\n"
        + "\n".join(f"  {f} -> segment_builder.{m}()" for (f, m) in sorted(missing))
    )
