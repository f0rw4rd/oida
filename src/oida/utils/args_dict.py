"""Normalizing argument mapping — ``'unit-id'`` and ``'unit_id'`` are one key.

Background
----------
argparse turns every ``--unit-id`` flag into a Namespace attribute spelled with
an underscore (``unit_id``). A large amount of legacy scanner code, however,
reads the *CLI* spelling with dashes (``args.get("unit-id")``). Historically
``connection._convert_args_to_dict`` reconciled the two by **dual-writing** every
key twice — once underscore, once hyphen — which is the "store each thing twice"
smell: it doubles the dict, and a writer that touches only one spelling leaves
the two silently out of sync.

The idiomatic fix is a mapping that treats ``-`` and ``_`` as equivalent and
stores each key exactly **once** (canonicalized to underscore, argparse's own
form). Lookups normalize on the way in, so both spellings resolve to the same
slot and no reader site has to change.

Why a ``dict`` subclass that overrides the *whole* accessor surface
-------------------------------------------------------------------
The clean way to write a normalizing mapping is ``collections.UserDict`` (it
derives ``get``/``update``/``in`` from three dunders). We instead subclass the
built-in ``dict`` **and override every access method explicitly**, because the
type has to stay a real ``dict``: ``connection._convert_args_to_dict`` and its
~15 protocol overrides are annotated ``-> Dict[str, Any]`` and the scanners they
feed are typed for ``dict``. A ``UserDict`` (a ``MutableMapping``, not a ``dict``)
would break that contract. Subclassing ``dict`` is only fragile when you forget
that its C-level ``get``/``update``/``__contains__``/``pop`` bypass an overridden
``__getitem__`` — so we override each of them here rather than relying on that
delegation.

Scope note
----------
This normalization is lossless-in-practice for OIDA: arg keys are consumed
internally only and never serialized back out to an external hyphenated format
(the sole key-iteration site is a debug log), so there is nothing to round-trip
and the "hides the source spelling" caveat does not bite here.
"""

from __future__ import annotations

from typing import Any, Iterable, Mapping, Optional, Union


class ArgsDict(dict):
    """A ``dict`` where hyphen and underscore key spellings are the same key.

    Keys are canonicalized to the underscore form (argparse's native spelling)
    on every insert and lookup, so ``d["unit-id"]`` and ``d["unit_id"]`` address
    one slot and the mapping never holds both. Non-string keys pass through
    unchanged.
    """

    @staticmethod
    def _norm(key: Any) -> Any:
        return key.replace("-", "_") if isinstance(key, str) else key

    def __init__(
        self,
        data: Optional[Union[Mapping[Any, Any], Iterable[Any]]] = None,
        **kwargs: Any,
    ) -> None:
        super().__init__()
        if data is not None:
            self.update(data)
        if kwargs:
            self.update(kwargs)

    # --- reads ---
    def __getitem__(self, key: Any) -> Any:
        return super().__getitem__(self._norm(key))

    def __contains__(self, key: Any) -> bool:
        return super().__contains__(self._norm(key))

    def get(self, key: Any, default: Any = None) -> Any:
        return super().get(self._norm(key), default)

    # --- writes ---
    def __setitem__(self, key: Any, value: Any) -> None:
        super().__setitem__(self._norm(key), value)

    def __delitem__(self, key: Any) -> None:
        super().__delitem__(self._norm(key))

    def setdefault(self, key: Any, default: Any = None) -> Any:
        return super().setdefault(self._norm(key), default)

    def pop(self, key: Any, *args: Any) -> Any:
        return super().pop(self._norm(key), *args)

    def update(self, *args: Any, **kwargs: Any) -> None:  # type: ignore[override]
        # Route every insert through __setitem__ so normalization always applies,
        # whether the source is a mapping, an iterable of pairs, or kwargs.
        if args:
            (other,) = args
            items = other.items() if isinstance(other, Mapping) else other
            for k, v in items:
                self[k] = v
        for k, v in kwargs.items():
            self[k] = v
