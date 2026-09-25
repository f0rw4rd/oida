"""Regression: connection._convert_args_to_dict stores each key ONCE.

Before the ArgsDict fix this method dual-wrote every key (``unit_id`` *and*
``unit-id``), so the result dict was double-sized and a later single-spelling
write could desync the two. Now it returns a normalizing ArgsDict: one slot per
key (underscore/canonical form), both spellings still resolve.
"""

from __future__ import annotations

import argparse
import types

from oida.connection import connection
from oida.utils.args_dict import ArgsDict


def _convert(ns: argparse.Namespace, ip: str = "10.0.0.5"):
    """Call the unbound method against a minimal stand-in (needs only .ip/.args)."""
    fake = types.SimpleNamespace(ip=ip, args=ns)
    return connection._convert_args_to_dict(fake)  # type: ignore[arg-type]


def test_no_dual_write_single_key_per_flag():
    ns = argparse.Namespace(unit_id=3, read_only=True, port=502, nothing=None)
    result = _convert(ns)

    assert isinstance(result, ArgsDict)
    # Underscore form is the only stored spelling...
    assert "unit_id" in result.keys()
    assert "unit-id" not in result.keys()
    # ...but the hyphenated CLI spelling still resolves (normalization).
    assert result["unit-id"] == 3
    assert result.get("unit-id") == 3


def test_port_remapped_to_rport_and_rhost_set():
    ns = argparse.Namespace(port=1502)
    result = _convert(ns, ip="192.168.1.9")
    assert result["rhost"] == "192.168.1.9"
    assert result["rport"] == 1502
    assert "port" not in result


def test_none_values_are_dropped():
    ns = argparse.Namespace(unit_id=None, keep=1)
    result = _convert(ns)
    assert "unit_id" not in result
    assert result["keep"] == 1


def test_no_key_stored_in_both_spellings():
    ns = argparse.Namespace(unit_id=1, read_class=2, max_depth=3)
    keys = list(_convert(ns).keys())
    # No key appears with a hyphen - canonical underscore only, no duplicates.
    assert all("-" not in k for k in keys)
    assert len(keys) == len(set(keys))
