"""Regression test: BACnet BitString application-tag prefix byte.

A BACnet application-tagged BitString encodes as::

    [unused-bits count byte][content octets ...]

The leading byte is a length/unused-bits prefix and is never bit content.
``_bacpypes3_enumerate_services`` / the object-types loop decoded with
``data[1:] if len(data) > 1 else data`` - the ``else data`` branch iterates
the PREFIX byte itself as content whenever the payload is a single byte
(empty bit string), so a response with a nonzero unused-bits byte
(e.g. ``b"\\x07"``) would report phantom supported services at indices 5-7.

``data[1:]`` is the correct unconditional form (already ``b""`` when the
payload carries no content octets).

The code under test is never monkey-patched; only the network boundary
(``app.request``) is mocked.
"""

import asyncio
import sys
import unittest
from pathlib import Path
from unittest.mock import Mock

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "src"))

from bacpypes3.apdu import ReadPropertyACK  # noqa: E402
from bacpypes3.basetypes import PropertyIdentifier  # noqa: E402
from bacpypes3.constructeddata import Any  # noqa: E402
from bacpypes3.primitivedata import Tag, TagClass, TagList  # noqa: E402

from oida.protocols.bacnet.mixins.objects import ObjectsMixin  # noqa: E402
from oida.protocols.bacnet.service_catalog import SERVICE_NAMES  # noqa: E402


class _RecordingLogger:
    def __init__(self):
        self.lines = []

    def display(self, msg):
        self.lines.append(msg)

    def success(self, msg):
        self.lines.append(msg)

    def debug(self, msg):
        pass

    def warning(self, msg):
        pass


class _Stub(ObjectsMixin):
    def __init__(self):
        self.logger = _RecordingLogger()


def _bitstring_any(payload: bytes) -> Any:
    """A decoded propertyValue holding an application bitString tag."""
    inst = Any.__new__(Any)
    inst.tagList = TagList([Tag(TagClass.application, 8, len(payload), payload)])
    return inst


def _ack_for(prop_name: str, payload: bytes) -> ReadPropertyACK:
    ack = ReadPropertyACK()
    ack.propertyIdentifier = PropertyIdentifier(prop_name)
    ack.propertyValue = _bitstring_any(payload)
    return ack


def _make_app(ack) -> Mock:
    app = Mock()

    async def request(_req, *_a, **_k):
        return ack

    app.request = request
    return app


class TestServicesBitStringPrefix(unittest.TestCase):
    def _run(self, payload: bytes):
        stub = _Stub()
        app = _make_app(_ack_for("protocolServicesSupported", payload))
        target = Mock()
        asyncio.run(stub._bacpypes3_enumerate_services(app, target, 1, 1.0))
        found = []
        for ln in stub.logger.lines:
            ln = ln.strip()
            if ln.startswith("- "):
                found.append(ln[2:].split("->")[0].strip())
        return found

    def test_normal_two_octet_content(self):
        """Content octets follow the prefix; bit 0 of the first content octet
        is service index 0."""
        found = self._run(b"\x00\x80")
        self.assertIn(SERVICE_NAMES[0], found)
        self.assertNotIn(SERVICE_NAMES[8], found)

    def test_single_byte_payload_is_prefix_only(self):
        """A 1-byte payload is ONLY the unused-bits count. It must never be
        decoded as content: no phantom services from its set bits."""
        found = self._run(b"\x07")  # malformed: unused=7, no content octets
        self.assertEqual(
            found,
            [],
            "the unused-bits prefix byte must not be decoded as service bits",
        )


if __name__ == "__main__":
    unittest.main()
