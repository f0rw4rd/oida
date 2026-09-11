"""Regression: SSDP XML-mode fallback must parse every header in the blob.

tshark can fold several SSDP headers into one ``http.unknown_header`` value
joined by CRLF. The listener stripped all newlines then split on the first
colon, keeping only the first header (typically NT) and silently dropping
USN -- the primary SSDP device identifier -- and NTS.
"""

import pytest

from oida.pcap.ssdp import SSDPPassiveListener

pytestmark = [pytest.mark.integration]


class _FakeXmlLayer:
    """Minimal XML-mode layer: get_field misses, _all_fields carries the blob."""

    def __init__(self, all_fields):
        self._all_fields = all_fields

    def get_field(self, name):  # used by BasePysharkListener.get_field
        return None


def test_multi_header_blob_yields_usn_and_nts():
    listener = SSDPPassiveListener(interface="lo", timeout=1)
    blob = "NT: upnp:rootdevice\r\nUSN: uuid:abcd-1234::upnp:rootdevice\r\nNTS: ssdp:alive"
    layer = _FakeXmlLayer({"http.unknown_header": blob})

    result = listener._extract_ssdp_fields_xml(layer)

    assert result is not None
    assert result.get("nt") == "upnp:rootdevice"
    assert result.get("usn") == "uuid:abcd-1234::upnp:rootdevice", (
        "USN dropped -- only the first header of the blob was parsed"
    )
    assert result.get("nts") == "ssdp:alive"


def test_escaped_crlf_blob_also_split():
    """Some captures render the separator as the literal backslash-r-n."""
    listener = SSDPPassiveListener(interface="lo", timeout=1)
    blob = "NT: upnp:rootdevice\\r\\nUSN: uuid:zzz::x\\r\\nNTS: ssdp:byebye"
    layer = _FakeXmlLayer({"http.unknown_header": blob})

    result = listener._extract_ssdp_fields_xml(layer)
    assert result.get("usn") == "uuid:zzz::x"
    assert result.get("nts") == "ssdp:byebye"
