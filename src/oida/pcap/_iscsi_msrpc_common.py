"""Shared interaction-recording helper for the iSCSI and MSRPC/DCERPC
passive listeners.

Both listeners build a ``ProtocolInteraction`` for the current packet, call
``self._record_interaction()`` with an identical parameter shape, and then
resolve which endpoint is the server vs. the client from the same
``is_response`` flag. This module single-sources that boilerplate; the two
protocols remain otherwise unrelated and keep their own field parsing.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, Optional, Tuple


class RecordInteractionMixin:
    """Mixin adding ``_record_and_resolve_endpoints`` to a listener.

    Expects the including class to provide ``self._record_interaction``
    (from ``PySharkListenerBase``) and to sit before it in the MRO.
    """

    def _record_and_resolve_endpoints(
        self,
        *,
        src_ip: str,
        dst_ip: str,
        src_mac: str,
        dst_mac: str,
        direction: str,
        operation: str,
        details: Dict[str, Any],
        summary: str,
        flow_id: str,
        src_port: int,
        dst_port: int,
        stream_id: str,
        is_response: bool,
        now: Optional[str] = None,
    ) -> Tuple[str, str, str, str]:
        """Record the interaction and resolve (server_ip, client_ip, server_mac, client_mac).

        Timestamps the interaction with ``datetime.now().isoformat()`` unless
        ``now`` is supplied (e.g. the caller needs the same timestamp for a
        further, related record), forwards it to ``self._record_interaction``,
        then derives the server/client endpoints from ``is_response`` (a
        response's source is the server; a request's destination is the
        server).
        """
        if now is None:
            now = datetime.now().isoformat()
        self._record_interaction(
            now,
            src_ip,
            dst_ip,
            direction,
            operation,
            details,
            summary,
            flow_id=flow_id,
            src_port=src_port,
            dst_port=dst_port,
            stream_id=stream_id,
        )

        if is_response:
            server_ip, client_ip = src_ip, dst_ip
            server_mac, client_mac = src_mac, dst_mac
        else:
            server_ip, client_ip = dst_ip, src_ip
            server_mac, client_mac = dst_mac, src_mac

        return server_ip, client_ip, server_mac, client_mac
