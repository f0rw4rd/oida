"""RED: ack-after-receive uses _send_and_receive (send + up-to-6 recv loop that
DISCARDS non-matching frames). Any genuine CP message arriving right after the
ack (e.g. the async StatusNotification for the NEXT connector, or MeterValues)
is consumed and lost. Fix: ack with a plain send."""

import json
from unittest.mock import MagicMock

from oida.protocols.ocpp import ocpp as OcppClass


def test_receive_status_notification_ack_does_not_consume_frames():
    inst = object.__new__(OcppClass)
    inst.results = {"data": {}}
    inst.logger = MagicMock()
    inst.scanner = MagicMock()

    received_frames = iter(
        [
            # 1) the StatusNotification CALL the helper waits for
            json.dumps(
                [
                    2,
                    "svr-1",
                    "StatusNotification",
                    {"connectorId": 1, "status": "Charging", "errorCode": "NoError"},
                ]
            ),
            # 2) a genuine follow-up CALL for the NEXT connector that arrives
            #    immediately after our ack -- must NOT be swallowed by the ack
            json.dumps(
                [
                    2,
                    "svr-2",
                    "StatusNotification",
                    {"connectorId": 2, "status": "Available", "errorCode": "NoError"},
                ]
            ),
        ]
    )

    loop = MagicMock()
    loop.is_closed.return_value = False

    import asyncio

    async def fake_recv():
        try:
            return next(received_frames)
        except StopIteration:
            raise asyncio.TimeoutError()

    inst.conn = MagicMock()
    inst.conn.recv = fake_recv
    inst.scanner._event_loop = loop

    ack_sends = []
    receives_during_ack = []

    def fake_send_and_receive(conn, msg, timeout=None):
        # A plain send-only ack: record and do NOT recv.
        # The buggy implementation uses _send_and_receive, which is a send+recv
        # exchange; we detect it by having it return None immediately after
        # recording that a recv WOULD consume the next frame.
        ack_sends.append(msg)
        receives_during_ack.append(True)  # _send_and_receive always recvs >= once
        return None

    inst.scanner._send_and_receive.side_effect = fake_send_and_receive

    import asyncio as _a

    real_loop = _a.new_event_loop()
    loop.run_until_complete.side_effect = real_loop.run_until_complete

    info = inst._receive_status_notification()

    assert info is not None and info.get("status") == "Charging", info
    # The ack must actually be SENT (via conn.send):
    assert inst.conn.send.called, "ack was never sent"
    # THE assertion: acking must not consume further frames.
    # If ack used send+recv, receives_during_ack would be non-empty.
    assert not receives_during_ack, (
        "ack used _send_and_receive (send+recv): the recv loop consumes "
        "subsequent CP CALL frames (the next connector's StatusNotification / "
        "async MeterValues), losing probe data"
    )
