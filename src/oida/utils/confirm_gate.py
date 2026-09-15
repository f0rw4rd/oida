"""Shared confirmation gate for destructive / live-write ICS operations.

Both the Layer-2 ``connection`` base (``oida.connection``) and the Layer-1
``BaseScanner`` base (``oida.utils.base_scanner``) mix this in, so *every*
scanner — CLI-dispatched or used as a library — reaches for the same
``require_confirm()`` idiom before actuating a dangerous action.

The framework adds ``--confirm`` and the per-protocol dangerous flags centrally
via ``proto_args_factory``; every gated help string promises
"(requires --confirm)". This mixin enforces that promise with one standard
check plus a standard failure log.
"""

from typing import Any, Optional


class ConfirmGateMixin:
    """Provides the canonical ``require_confirm`` gate.

    Consumers must expose ``self.args`` (argparse ``Namespace``, a dict, or the
    ``_ArgsBridge`` used by Layer-1 scanners) and ``self.logger`` (an
    ``ics_logger`` with a ``.fail()`` method).
    """

    args: Any
    logger: Any

    def _confirm_flag(self) -> bool:
        """Read the ``confirm`` flag regardless of how ``args`` is shaped.

        The CLI passes an argparse ``Namespace`` and Layer-1 scanners may hold
        the dash-normalizing ``_ArgsBridge`` — both support attribute access, so
        that is the primary path. A plain ``dict`` (Layer-1 library usage) is
        read via ``.get``. Attribute access is tried first so an object that
        happens to expose a ``.get`` (e.g. a test ``MagicMock``) still reports
        the real flag rather than a truthy stand-in.
        """
        args = self.args
        if isinstance(args, dict):
            return bool(args.get("confirm", False))
        return bool(getattr(args, "confirm", False))

    def require_confirm(self, action_name: str, *, detail: Optional[str] = None) -> bool:
        """Canonical gate for destructive / live-write operations.

        This is the *single idiom* every protocol must use before actuating a
        dangerous action (write/control/start/stop/fuzz, etc.). A new gated
        action only needs::

            if not self.require_confirm("--write-value"):
                return

        When the default failure line is not specific enough — e.g. the action
        needs to spell out exactly which writes it can emit — pass ``detail``
        with the full message to log instead::

            if not self.require_confirm(
                "--raw-fc",
                detail="--raw-fc sends arbitrary function codes ... requires --confirm",
            ):
                return

        Args:
            action_name: Human-readable name of the gated action (e.g.
                ``"--write-value"``) used in the default failure message.
            detail: Optional full failure message that replaces the default
                (use when a richer safety explanation is warranted).

        Returns:
            True if ``--confirm`` was supplied and the action may proceed;
            False (after logging a standard failure line) otherwise.
        """
        if self._confirm_flag():
            return True
        self.logger.fail(detail or f"{action_name} requires --confirm (dangerous operation)")
        return False
