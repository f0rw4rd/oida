"""Hostile-response parsing tests for bacnet / iec104 / can / knx.

Every test here feeds a MALFORMED, TRUNCATED or otherwise hostile response
(the kind an untrusted peer controls) straight into the real parse function
and asserts the scanner degrades gracefully instead of dying with an
unhandled ``IndexError`` / ``struct.error`` / ``ValueError``, hanging, or
over-allocating.

Each test names the concrete defect it pins.
"""

import asyncio
import unittest
from types import SimpleNamespace


from oida.protocols.can.mixins.canopen import CANopenMixin
from oida.protocols.can.mixins.isotp import ISOTPMixin
from oida.protocols.can.mixins.uds import UDSMixin
from tests.service_gate import require_import


class _Logger:
    """Silent logger stub with the surface the mixins touch."""

    def debug(self, *a, **k):
        pass

    def display(self, *a, **k):
        pass

    def success(self, *a, **k):
        pass

    def fail(self, *a, **k):
        pass

    def warning(self, *a, **k):
        pass


class _FakeMessage:
    def __init__(self, arbitration_id, data, is_remote_frame=False):
        self.arbitration_id = arbitration_id
        self.data = data
        self.is_remote_frame = is_remote_frame


class _FakeBus:
    """Bus yielding a pre-seeded frame list, then None (timeout)."""

    def __init__(self, frames):
        self._frames = list(frames)
        self.sent = []

    def send(self, msg):
        self.sent.append(msg)

    def recv(self, timeout=None):
        if self._frames:
            return self._frames.pop(0)
        return None


class _CANHarness(UDSMixin, ISOTPMixin, CANopenMixin):
    def __init__(self):
        self.logger = _Logger()


# ---------------------------------------------------------------------------
# CAN / ISO-TP
# ---------------------------------------------------------------------------


class TestISOTPTruncatedFirstFrame(unittest.TestCase):
    """ISO-TP First Frame with a 1-byte payload.

    ``isotp_recv`` only checked that the frame was non-empty before reading
    ``first[1]`` for the 12-bit total length -> IndexError on a DLC=1 FF.
    """

    def test_isotp_recv_survives_one_byte_first_frame(self):
        harness = _CANHarness()
        # 0x10 = First Frame PCI, length nibble 0, and NOTHING else.
        bus = _FakeBus([_FakeMessage(0x7E8, b"\x10")])

        result = harness.isotp_recv(bus, 0x7E0, 0x7E8, timeout=0.1)

        self.assertIsNone(result)

    def test_uds_scan_path_survives_one_byte_first_frame(self):
        """Same frame through the real UDS receive path."""
        harness = _CANHarness()
        bus = _FakeBus([_FakeMessage(0x7E8, b"\x10")])

        self.assertIsNone(harness._recv_uds_response(bus, 0x7E0, timeout=0.1))

    def test_assemble_isotp_data_survives_one_byte_first_frame(self):
        """The shared reassembler must not IndexError on a truncated FF."""
        harness = _CANHarness()

        self.assertIsNone(harness._assemble_isotp_data([b"\x10"]))

    def test_wellformed_first_frame_still_reassembles(self):
        """No semantic change for a valid FF + CF exchange."""
        harness = _CANHarness()
        # FF: total length 10, carries 6 data bytes.
        ff = _FakeMessage(0x7E8, bytes([0x10, 0x0A, 1, 2, 3, 4, 5, 6]))
        # CF SN=1 carrying the remaining 4 bytes.
        cf = _FakeMessage(0x7E8, bytes([0x21, 7, 8, 9, 10, 0, 0, 0]))
        bus = _FakeBus([ff, cf])

        result = harness.isotp_recv(bus, 0x7E0, 0x7E8, timeout=0.5)

        self.assertIsNotNone(result)
        source_id, payload = result
        self.assertEqual(source_id, 0x7E8)
        self.assertEqual(payload, bytes([1, 2, 3, 4, 5, 6, 7, 8, 9, 10]))

    def test_wellformed_single_frame_still_parses(self):
        harness = _CANHarness()
        bus = _FakeBus([_FakeMessage(0x7E8, bytes([0x02, 0x7E, 0x00, 0, 0, 0, 0, 0]))])

        result = harness.isotp_recv(bus, 0x7E0, 0x7E8, timeout=0.5)

        self.assertEqual(result, (0x7E8, bytes([0x7E, 0x00])))


# ---------------------------------------------------------------------------
# CAN / CANopen SDO
# ---------------------------------------------------------------------------


class TestCANopenEmptySDOResponse(unittest.TestCase):
    """A DLC=0 data frame on the SDO TX COB-ID.

    ``_recv_sdo_response`` returns ``b''`` for it (an empty data frame is not
    a remote frame, so it passes the filter), and the callers indexed
    ``resp_data[0]`` unconditionally -> IndexError.
    """

    def test_sdo_read_survives_empty_initiate_response(self):
        harness = _CANHarness()
        bus = _FakeBus([_FakeMessage(0x581, b"")])

        resp = harness.canopen_sdo_read(bus, node_id=1, index=0x1000, subindex=0, timeout=0.1)

        self.assertTrue(resp.error)

    def test_sdo_read_survives_empty_segment_response(self):
        """Segmented upload where every segment reply is a DLC=0 frame."""
        harness = _CANHarness()
        # Initiate-upload response: SCS=2, not expedited, size indicated (8 bytes).
        initiate = _FakeMessage(0x581, bytes([0x41, 0x00, 0x10, 0x00, 0x08, 0, 0, 0]))
        bus = _FakeBus([initiate, _FakeMessage(0x581, b""), _FakeMessage(0x581, b"")])

        resp = harness.canopen_sdo_read(bus, node_id=1, index=0x1000, subindex=0, timeout=0.1)

        self.assertTrue(resp.error)

    def test_sdo_read_survives_endless_empty_segment_responses(self):
        """A peer that answers every segment request with a DLC=0 frame."""
        harness = _CANHarness()
        initiate = bytes([0x41, 0x00, 0x10, 0x00, 0x08, 0, 0, 0])

        class _Bus(_FakeBus):
            def __init__(self):
                super().__init__([])
                self._first = True

            def recv(self, timeout=None):
                if self._first:
                    self._first = False
                    return _FakeMessage(0x581, initiate)
                return _FakeMessage(0x581, b"")

        resp = harness.canopen_sdo_read(_Bus(), node_id=1, index=0x1000, subindex=0, timeout=0.05)

        self.assertTrue(resp.error)

    def test_expedited_sdo_read_still_works(self):
        """No semantic change for a well-formed expedited upload."""
        harness = _CANHarness()
        # SCS=2, expedited, size indicated, n=0 -> 4 data bytes DE AD BE EF.
        good = _FakeMessage(0x581, bytes([0x43, 0x00, 0x10, 0x00, 0xDE, 0xAD, 0xBE, 0xEF]))
        bus = _FakeBus([good])

        resp = harness.canopen_sdo_read(bus, node_id=1, index=0x1000, subindex=0, timeout=0.2)

        self.assertFalse(resp.error)
        self.assertEqual(resp.data, b"\xde\xad\xbe\xef")


# ---------------------------------------------------------------------------
# BACnet
# ---------------------------------------------------------------------------

bacpypes3 = require_import("bacpypes3")


class _Tag:
    def __init__(self, data: bytes):
        self.tag_data = data

    def __str__(self):  # must not contain "open"/"close" (the parser skips those)
        return "tag"


def _response(data: bytes):
    return SimpleNamespace(propertyValue=SimpleNamespace(tagList=[_Tag(data)]))


class _FakeBACnetApp:
    """App that reports an objectList of exactly one object, then stonewalls.

    `objectList` index 0 -> list length 1; index 1 -> the object identifier
    under test. Every other read returns None (no response), which is what a
    terse device looks like.
    """

    def __init__(self, obj_type: int, instance: int = 1):
        self._oid_bytes = ((((obj_type & 0x3FF) << 22) | instance) & 0xFFFFFFFF).to_bytes(4, "big")
        self.reads = 0

    async def request(self, req):
        self.reads += 1
        prop = str(req.propertyIdentifier)
        index = getattr(req, "propertyArrayIndex", None)
        if prop == "object-list" or prop == "objectList":
            if index == 0:
                return _response(b"\x01")  # list length = 1
            if index == 1:
                return _response(self._oid_bytes)
        return None


class _BACnetHarness:
    def __init__(self):
        from oida.protocols.bacnet.mixins.objects import ObjectsMixin

        self.__class__ = type("_H", (ObjectsMixin,), {})
        self.logger = _Logger()
        self.args = SimpleNamespace(max_objects=10)
        self.objects = {}


class TestBACnetProprietaryObjectType(unittest.TestCase):
    """A device whose objectList contains a proprietary object type (128-1023).

    `_bacpypes3_deep_enum` built the ObjectIdentifier from the synthetic name
    `f"type-{obj_type}"`, which bacpypes3 rejects with ValueError. That escaped
    the walk loop and aborted the whole scan, discarding every result for the
    host. Proprietary types are legitimate -- discovery.py even probes 128-170
    for them, addressing them numerically.
    """

    def _run(self, obj_type: int):
        harness = _BACnetHarness()
        app = _FakeBACnetApp(obj_type)
        asyncio.run(harness._bacpypes3_deep_enum(app, "1.2.3.4", 599, timeout=0.1))
        return harness

    def test_deep_enum_survives_proprietary_object_type(self):
        harness = self._run(128)

        # The walk completed and recorded the proprietary object.
        self.assertIn(599, harness.objects)
        self.assertIn("type-128", harness.objects[599])

    def test_deep_enum_survives_max_proprietary_object_type(self):
        harness = self._run(1023)

        self.assertIn("type-1023", harness.objects[599])

    def test_deep_enum_standard_object_type_unchanged(self):
        """No semantic change for a standard type (0 = analogInput)."""
        harness = self._run(0)

        self.assertIn(599, harness.objects)
        self.assertEqual(list(harness.objects[599]), ["analogInput"])


class TestBACnetSCFrameSizeCap(unittest.TestCase):
    """A hostile BACnet/SC hub must not be able to make us buffer unbounded RAM.

    `SCConnection.open()` passed `max_size=None` to `websockets.connect`,
    disabling the library's per-message cap, so a malicious peer could stream
    an arbitrarily large frame that is fully buffered by `recv()`.
    """

    def test_sc_connect_bounds_websocket_message_size(self):
        require_import("websockets")
        from unittest import mock

        from oida.protocols.bacnet import sc_link

        captured = {}

        async def _fake_connect(uri, **kwargs):
            captured.update(kwargs)
            raise RuntimeError("stop after capturing connect() kwargs")

        conn = sc_link.SCConnection("wss://198.51.100.1:47808", None, timeout=0.1)
        with mock.patch.object(sc_link.websockets, "connect", _fake_connect):
            with self.assertRaises(RuntimeError):
                asyncio.run(conn.open())

        self.assertIsNotNone(
            captured.get("max_size"),
            "websockets.connect must cap max_size; None lets a hostile SC peer OOM the scanner",
        )
        self.assertLessEqual(captured["max_size"], 16 * 1024 * 1024)


class TestBACnetSCReaderLoopSurvivesBadNPDU(unittest.TestCase):
    """One undecodable NPDU must not permanently kill the SC reader task.

    `_read_loop` only caught `ConnectionClosed`, so any exception raised while
    dispatching an attacker-controlled NPDU upstream killed the reader created
    in `__init__`. Nothing restarts or reports it, so every later request
    silently burns its full timeout -- the scan stalls instead of failing.
    """

    def test_reader_survives_a_poisoned_npdu(self):
        require_import("websockets")

        from oida.protocols.bacnet import sc_link

        frame = bytes.fromhex("010c00070102030405060a0b0c0d0e0f010010")

        class _FakeWS:
            def __init__(self):
                self.closed = False

            def __aiter__(self):
                async def _gen():
                    yield frame  # poisoned: dispatch raises
                    yield frame  # must still be delivered
                    await asyncio.sleep(0.05)

                return _gen()

            async def close(self):
                self.closed = True

        async def _run():
            from bacpypes3.pdu import VirtualAddress

            ws = _FakeWS()
            link = sc_link.SCLinkLayer(
                ws,
                VirtualAddress(b"\x01\x02\x03\x04\x05\x06"),
                VirtualAddress(b"\x0a\x0b\x0c\x0d\x0e\x0f"),
            )
            delivered = []

            async def _response(npdu):
                delivered.append(npdu)
                if len(delivered) == 1:
                    raise ValueError("malformed NPCI blew up the upstream dispatch")

            link.response = _response
            await asyncio.sleep(0.2)
            await link.close()
            return delivered

        delivered = asyncio.run(_run())

        self.assertGreaterEqual(
            len(delivered),
            2,
            "reader task died on the first bad NPDU and stopped delivering frames",
        )


if __name__ == "__main__":
    unittest.main()
