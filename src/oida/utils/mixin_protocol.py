"""
Type stubs for mixin classes.

Mixin classes reference attributes (self.logger, self.args, etc.) that are
defined on the base classes (NetworkConnection, BaseScanner, etc.), not on
the mixin itself.  This causes MyPy ``attr-defined`` errors.

By declaring a ``Protocol`` with the common attributes, each mixin can
inherit from it *only during type-checking* (guarded by ``TYPE_CHECKING``),
giving MyPy the information it needs without affecting runtime behavior.

Usage in a mixin file::

    from __future__ import annotations
    from typing import TYPE_CHECKING

    if TYPE_CHECKING:
        from oida.utils.mixin_protocol import ScannerMixin as _ScannerBase
    else:
        _ScannerBase = object

    class MyMixin(_ScannerBase):
        ...
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Dict, Protocol, runtime_checkable

if TYPE_CHECKING:
    import argparse
    from collections import defaultdict

    from oida.utils.ics_logger import ICSLogger


@runtime_checkable
class ScannerMixin(Protocol):
    """Common attributes provided by connection / BaseScanner base classes.

    Mixins that are composed into a scanner class at runtime can list this
    as a base *under TYPE_CHECKING only* so that MyPy sees the attributes.
    """

    logger: ICSLogger
    args: argparse.Namespace | Dict[str, Any]
    results: dict | defaultdict
    conn: Any
    host: str
    ip: str
    hostname: str
    db: Any
    debug: bool
    timeout: int
    read_only: bool
    interface: str
    scanner: Any
