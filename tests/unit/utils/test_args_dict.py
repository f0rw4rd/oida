"""Unit tests for the normalizing ArgsDict.

ArgsDict is the fix for the dual-key smell: hyphen and underscore spellings of a
key must resolve to a single slot, so scanners that read the CLI spelling
(``args.get("unit-id")``) and code that writes the argparse spelling
(``result["unit_id"] = ...``) never drift apart, and the dict never stores a key
twice.
"""

from __future__ import annotations

import pytest

from oida.utils.args_dict import ArgsDict


def test_hyphen_and_underscore_are_the_same_slot():
    d = ArgsDict()
    d["unit-id"] = 7
    assert d["unit_id"] == 7
    assert d["unit-id"] == 7
    # Stored exactly once, canonicalized to the underscore form.
    assert list(d.keys()) == ["unit_id"]


def test_last_write_wins_across_spellings():
    d = ArgsDict()
    d["read-only"] = True
    d["read_only"] = False
    assert d["read-only"] is False
    assert len(d) == 1


def test_get_and_contains_normalize():
    d = ArgsDict({"scan-range": "0-100"})
    assert d.get("scan_range") == "0-100"
    assert d.get("scan-range") == "0-100"
    assert "scan_range" in d
    assert "scan-range" in d
    assert d.get("missing-key", "default") == "default"


def test_construction_from_mapping_normalizes():
    d = ArgsDict({"unit-id": 1, "read-class": 3})
    assert d["unit_id"] == 1
    assert d["read_class"] == 3
    assert set(d.keys()) == {"unit_id", "read_class"}


def test_construction_from_kwargs_normalizes():
    # rhost/rport style construction used by _convert_args_to_dict.
    d = ArgsDict(rhost="10.0.0.1")
    assert d["rhost"] == "10.0.0.1"


def test_update_pop_setdefault_normalize():
    d = ArgsDict()
    d.update({"max-depth": 3})
    assert d["max_depth"] == 3
    assert d.setdefault("max-depth", 9) == 3  # existing, not overwritten
    assert d.setdefault("new-flag", True) is True
    assert d.pop("max-depth") == 3
    assert "max_depth" not in d


def test_non_string_keys_pass_through():
    d = ArgsDict()
    d[42] = "answer"
    assert d[42] == "answer"


def test_delitem_normalizes():
    d = ArgsDict({"unit-id": 1})
    del d["unit_id"]
    assert "unit-id" not in d


def test_is_a_real_dict():
    # The whole reason we subclass dict (not UserDict): the _convert_args_to_dict
    # contract is `-> Dict[str, Any]` and scanners are typed for dict.
    assert isinstance(ArgsDict(), dict)


@pytest.mark.parametrize(
    "written, read",
    [
        ("unit-id", "unit_id"),
        ("unit_id", "unit-id"),
        ("read-class", "read_class"),
        ("no-emergency-monitor", "no_emergency_monitor"),
    ],
)
def test_write_one_spelling_read_the_other(written, read):
    d = ArgsDict()
    d[written] = "v"
    assert d[read] == "v"
