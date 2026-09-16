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

    Optional typo detection (``known_keys``)
    ----------------------------------------
    argparse always materializes *every* declared flag as a Namespace attribute
    (``None`` when unset), so ``set(vars(namespace))`` is the complete declared
    arg surface. Passing that as ``known_keys`` lets this mapping tell a genuine
    typo (``args.get("unti_id")`` — a key that was *never a flag*) apart from a
    legitimately-absent optional (``args.get("timeout")`` when ``timeout=None``,
    which was dropped on the way in but is still a declared key). Reads of keys
    that are neither present nor declared are recorded in
    :attr:`undeclared_reads`; with ``strict=True`` they raise instead — off by
    default so production behavior is unchanged.

    .. warning::
       Strict mode is **experimental and not yet CI-safe.** ``known_keys`` today
       is only the argparse dest surface, but some protocols *synthesize* dict
       keys that were never flags (e.g. dnp3's ``cli_runner`` writes
       ``read-class``/``master-address``/``control``). Reading such a key when
       it happens to be absent would raise a false positive under ``strict``.
       Do not enable ``OIDA_STRICT_ARGS`` in CI until those synthesized/renamed
       keys are folded into ``known_keys``.
    """

    # Class-level defaults so construction paths that bypass __init__
    # (dict.copy, fromkeys, unpickling) never hit a missing-attribute error.
    _known_keys: Optional[frozenset] = None
    _strict: bool = False

    @staticmethod
    def _norm(key: Any) -> Any:
        return key.replace("-", "_") if isinstance(key, str) else key

    def __init__(
        self,
        data: Optional[Union[Mapping[Any, Any], Iterable[Any]]] = None,
        *,
        known_keys: Optional[Iterable[Any]] = None,
        strict: bool = False,
        **kwargs: Any,
    ) -> None:
        super().__init__()
        self._known_keys = (
            frozenset(self._norm(k) for k in known_keys) if known_keys is not None else None
        )
        self._strict = strict
        self._undeclared_reads: set = set()
        if data is not None:
            self.update(data)
        if kwargs:
            self.update(kwargs)

    # --- typo detection ---
    def _note_read(self, norm_key: Any) -> None:
        """Record/raise on a read of a key that is neither present nor declared."""
        known = self._known_keys
        if known is None or norm_key in known or super().__contains__(norm_key):
            return
        self._undeclared_reads.add(norm_key)
        if self._strict:
            raise KeyError(
                f"undeclared argument key {norm_key!r} "
                f"(not among declared flags: {sorted(known)!r}) — likely a typo"
            )

    @property
    def undeclared_reads(self) -> "set":
        """Normalized keys read but neither present nor declared (typo suspects)."""
        return set(getattr(self, "_undeclared_reads", set()))

    # --- reads ---
    def __getitem__(self, key: Any) -> Any:
        norm = self._norm(key)
        self._note_read(norm)
        return super().__getitem__(norm)

    def __contains__(self, key: Any) -> bool:
        norm = self._norm(key)
        self._note_read(norm)
        return super().__contains__(norm)

    def get(self, key: Any, default: Any = None) -> Any:
        norm = self._norm(key)
        self._note_read(norm)
        return super().get(norm, default)

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

    # --- copy / merge: keep the ArgsDict type + normalization ---
    # The built-in dict.copy(), `|`, `|=` and fromkeys() are implemented in C and
    # bypass the overrides above, silently returning a plain (un-normalizing)
    # dict or, for `|=`, storing a raw un-normalized key. Override them so a key
    # never escapes normalization.
    def copy(self) -> "ArgsDict":
        return ArgsDict(self, known_keys=self._known_keys, strict=self._strict)

    def __copy__(self) -> "ArgsDict":
        return self.copy()

    def __or__(self, other: Mapping[Any, Any]) -> "ArgsDict":
        # Preserve this operand's typo-detection config on the merge result.
        merged = ArgsDict(self, known_keys=self._known_keys, strict=self._strict)
        merged.update(other)
        return merged

    def __ror__(self, other: Mapping[Any, Any]) -> "ArgsDict":
        # ``other | self`` — self is the ArgsDict; carry its config forward.
        merged = ArgsDict(other, known_keys=self._known_keys, strict=self._strict)
        merged.update(self)
        return merged

    def __ior__(self, other: Mapping[Any, Any]) -> "ArgsDict":  # type: ignore[override]
        # Narrower `other` type than dict.__ior__ (mapping only, which is all we
        # merge here); route through update() so keys are normalized rather than
        # C-level in-place stored raw.
        self.update(other)
        return self

    @classmethod
    def fromkeys(cls, iterable: Iterable[Any], value: Any = None) -> "ArgsDict":  # type: ignore[override]
        out = cls()
        for k in iterable:
            out[k] = value
        return out
