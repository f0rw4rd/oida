"""
BACnet/SC link layer + connect handshake for bacpypes3.

bacpypes3 0.0.106 ships an SC *transport* (websocket client + a BVLC-SC codec)
but NO connect handshake and NO bridge to the Application/NSAP. This module
supplies both, so the existing BACnet application mixins ride over SC unchanged:

  * SCConnection.open()  — opens the direct-connect (or hub) websocket with a
    caller-supplied TLS context, runs the BVLC-SC Connect-Request/Connect-Accept
    handshake, and returns the negotiated peer VMAC.
  * SCLinkLayer        — a Server[PDU] bound under app.nsap that wraps outbound
    NPDUs in BVLC-SC EncapsulatedNPDU frames and unwraps inbound ones.

Verified end-to-end (TLS 1.3 mutual-auth ReadProperty) against bacnet-stack
1.4.4's BSC server in direct-connect mode.
"""

from __future__ import annotations

import asyncio
import uuid as uuidmod
from typing import Optional

import websockets

from bacpypes3.pdu import PDU, VirtualAddress
from bacpypes3.comm import Server
from bacpypes3.sc.bvll import LPCI, ConnectRequest, ConnectAccept, EncapsulatedNPDU

# WebSocket subprotocols that select SC topology (shared by both stacks).
DIRECT_SUBPROTOCOL = "dc.bsc.bacnet.org"
HUB_SUBPROTOCOL = "hub.bsc.bacnet.org"

# SC maxima advertised in the Connect-Request (bacnet-stack defaults).
_MAX_BVLC_LEN = 1476
_MAX_NPDU_LEN = 1497

# Hard ceiling on a single inbound websocket message. The peer is untrusted, and
# our advertised receive maximum is _MAX_BVLC_LEN, so this is orders of magnitude
# more than any conforming frame -- it exists purely so a hostile hub cannot make
# us buffer unbounded memory.
_MAX_WS_MESSAGE = 1 << 20


class SCLinkLayer(Server):
    """A BACnet/SC link layer bound under the NSAP.

    Downstream NPDUs arrive via indication() and are framed as BVLC-SC
    EncapsulatedNPDU over the single websocket; inbound frames are BVLL-decoded
    and the encapsulated NPDU is pushed upstream via response().
    """

    def __init__(
        self,
        websocket,
        local_vmac: VirtualAddress,
        peer_vmac: VirtualAddress,
        logger=None,
    ) -> None:
        super().__init__()
        self.websocket = websocket
        self.local_vmac = local_vmac
        self.peer_vmac = peer_vmac
        self.logger = logger
        self._msg_id = 1
        self._reader = asyncio.ensure_future(self._read_loop())

    def _next_id(self) -> int:
        self._msg_id = (self._msg_id + 1) & 0xFFFF
        return self._msg_id

    async def indication(self, npdu: PDU) -> None:
        enc = EncapsulatedNPDU(npdu.pduData)
        enc.bvlcFunction = LPCI.encapsulatedNPDU
        enc.bvlcMessageID = self._next_id()
        enc.bvlcOriginatingVirtualAddress = self.local_vmac
        enc.bvlcDestinationVirtualAddress = self.peer_vmac
        await self.websocket.send(bytes(enc.encode().pduData))

    async def _read_loop(self) -> None:
        try:
            async for raw in self.websocket:
                # LPCI.decode CONSUMES the BVLC-SC header bytes from the working
                # PDU, leaving the encapsulated NPDU as the remainder.
                work = PDU(raw)
                try:
                    lpci = LPCI.decode(work)
                except Exception:
                    continue
                if lpci.bvlcFunction != LPCI.encapsulatedNPDU:
                    continue
                npdu = PDU(bytes(work.pduData))
                npdu.pduSource = self.peer_vmac
                try:
                    await self.response(npdu)
                except Exception as e:
                    # The NPDU is peer-controlled; a decode failure upstream must
                    # not kill the reader task. If it did, the failure would be
                    # silent ("Task exception was never retrieved") and every
                    # later request would stall for its full timeout.
                    if self.logger:
                        self.logger.debug(f"BACnet/SC upstream dispatch failed: {e}")
        except websockets.ConnectionClosed:
            pass

    async def close(self) -> None:
        if self._reader and not self._reader.done():
            self._reader.cancel()
        try:
            await self.websocket.close()
        except Exception:
            pass


class SCConnection:
    """Owns the SC websocket + handshake; produces an SCLinkLayer."""

    def __init__(
        self,
        uri: str,
        ssl_context,
        *,
        hub: bool = False,
        timeout: float = 10.0,
    ) -> None:
        self.uri = uri
        self.ssl_context = ssl_context
        self.hub = hub
        self.timeout = timeout
        self.websocket = None
        self.local_vmac = VirtualAddress(b"\x01\x02\x03\x04\x05\x06")
        self.local_uuid = uuidmod.uuid4()
        self.peer_vmac: Optional[VirtualAddress] = None

    @property
    def subprotocol(self) -> str:
        return HUB_SUBPROTOCOL if self.hub else DIRECT_SUBPROTOCOL

    async def open(self) -> "VirtualAddress":
        """Open the websocket and run the BVLC-SC connect handshake.

        Returns the negotiated peer VMAC (the address used to reach the device).
        Raises on TLS failure, websocket failure, or a non-Connect-Accept reply.
        """
        self.websocket = await asyncio.wait_for(
            websockets.connect(
                self.uri,
                ssl=self.ssl_context,
                subprotocols=[websockets.Subprotocol(self.subprotocol)],
                max_size=_MAX_WS_MESSAGE,
            ),
            timeout=self.timeout,
        )

        cr = ConnectRequest(
            vmac_address=self.local_vmac,
            device_uuid=self.local_uuid,
            maximum_bvlc_length=_MAX_BVLC_LEN,
            maximum_npdu_length=_MAX_NPDU_LEN,
        )
        cr.bvlcFunction = LPCI.connectRequest
        cr.bvlcMessageID = 1
        await self.websocket.send(bytes(cr.encode().pduData))

        raw = await asyncio.wait_for(self.websocket.recv(), timeout=self.timeout)
        lpci = LPCI.decode(PDU(raw))
        if lpci.bvlcFunction != LPCI.connectAccept:
            raise RuntimeError(
                f"BACnet/SC handshake failed: expected Connect-Accept, "
                f"got BVLC function 0x{lpci.bvlcFunction:02x}"
            )
        ca = ConnectAccept.decode(PDU(raw))
        self.peer_vmac = ca.vmac_address
        return self.peer_vmac

    def make_link_layer(self, logger=None) -> SCLinkLayer:
        if self.websocket is None or self.peer_vmac is None:
            raise RuntimeError("open() must succeed before make_link_layer()")
        return SCLinkLayer(self.websocket, self.local_vmac, self.peer_vmac, logger=logger)

    def peer_cipher(self):
        """(cipher_name, tls_version, secret_bits) of the live TLS session."""
        if self.websocket is None:
            return None
        try:
            return self.websocket.transport.get_extra_info("cipher")
        except Exception:
            return None

    def peer_cert_der(self):
        """The peer (server) certificate in DER form, or None."""
        if self.websocket is None:
            return None
        try:
            sslobj = self.websocket.transport.get_extra_info("ssl_object")
            if sslobj is None:
                return None
            return sslobj.getpeercert(binary_form=True)
        except Exception:
            return None

    async def close(self) -> None:
        if self.websocket is not None:
            try:
                await self.websocket.close()
            except Exception:
                pass
