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


# --- copy / merge keep the type and its normalization -------------------------
# The built-in dict.copy()/`|`/`|=` are C-level and bypass the overrides,
# which would silently hand back a plain (un-normalizing) dict or, worse for
# `|=`, store a raw un-normalized key unreachable via the class's own accessors.


def test_copy_returns_argsdict_that_still_normalizes():
    d = ArgsDict({"unit-id": 1})
    c = d.copy()
    assert isinstance(c, ArgsDict)
    assert c["unit_id"] == 1
    assert c["unit-id"] == 1  # normalization survived the copy


def test_or_merge_returns_normalizing_argsdict():
    merged = ArgsDict({"unit-id": 1}) | {"read-class": 3}
    assert isinstance(merged, ArgsDict)
    assert merged["unit_id"] == 1
    assert merged["read_class"] == 3
    assert set(merged.keys()) == {"unit_id", "read_class"}


def test_ror_merge_from_plain_dict_left_operand():
    merged = {"read-class": 3} | ArgsDict({"unit-id": 1})
    assert isinstance(merged, ArgsDict)
    assert merged["read_class"] == 3
    assert merged["unit_id"] == 1


def test_ior_normalizes_instead_of_storing_raw_key():
    d = ArgsDict()
    d |= {"scan-range": "0-100"}
    # The landmine: a C-level |= would store the literal "scan-range" key,
    # unreachable via d["scan_range"]. Overriding routes it through __setitem__.
    assert d["scan_range"] == "0-100"
    assert list(d.keys()) == ["scan_range"]


def test_fromkeys_normalizes():
    d = ArgsDict.fromkeys(["unit-id", "read-class"], 0)
    assert isinstance(d, ArgsDict)
    assert set(d.keys()) == {"unit_id", "read_class"}


# --- optional typo detection (known_keys / strict) ----------------------------


def test_known_keys_off_by_default_no_recording():
    d = ArgsDict({"unit-id": 1})
    assert d.get("totally-made-up") is None
    assert d.undeclared_reads == set()  # no known_keys -> nothing tracked


def test_declared_but_absent_optional_is_not_a_typo():
    # timeout is a declared flag that happened to be None (dropped on the way in).
    d = ArgsDict({"unit-id": 1}, known_keys={"unit_id", "timeout"})
    assert d.get("timeout") is None
    assert d.undeclared_reads == set()


def test_undeclared_read_is_recorded_non_strict():
    d = ArgsDict({"unit-id": 1}, known_keys={"unit_id"})
    assert d.get("unti-id") is None  # typo
    assert d.undeclared_reads == {"unti_id"}


def test_strict_raises_on_undeclared_read():
    d = ArgsDict({"unit-id": 1}, known_keys={"unit_id"}, strict=True)
    with pytest.raises(KeyError, match="likely a typo"):
        d.get("unti-id")


def test_strict_does_not_raise_for_declared_or_present_keys():
    d = ArgsDict({"unit-id": 1}, known_keys={"unit_id", "timeout"}, strict=True)
    assert d.get("unit-id") == 1  # present
    assert d.get("timeout") is None  # declared, absent - fine


def test_copy_preserves_known_keys_and_strict():
    # Regression: copy() used to reconstruct via ArgsDict(self) without
    # forwarding known_keys/strict, silently disabling typo detection on copies.
    d = ArgsDict({"unit-id": 1}, known_keys={"unit_id"}, strict=True)
    c = d.copy()
    with pytest.raises(KeyError, match="likely a typo"):
        c.get("unti-id")


def test_or_merge_preserves_known_keys_and_strict():
    d = ArgsDict({"unit-id": 1}, known_keys={"unit_id"}, strict=True)
    merged = d | {"unit-id": 2}
    with pytest.raises(KeyError, match="likely a typo"):
        merged.get("bogus")


def test_ror_merge_preserves_argsdict_operand_config():
    d = ArgsDict({"unit-id": 1}, known_keys={"unit_id"}, strict=True)
    merged = {"unit-id": 2} | d
    with pytest.raises(KeyError, match="likely a typo"):
        merged.get("bogus")
