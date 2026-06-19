"""Unit tests for IPP attribute name/value pairing.

These tests exercise IPPPassiveListener._extract_attributes directly with a
fake tshark layer, so they need neither pyshark nor tshark.

Regression guard for the bug where ipp.name (every attribute name) was zipped
positionally against ipp.charstring_value (only the string-typed values). Those
two flattened, comma-joined lists generally have different lengths, so zipping
them paired an attribute name with the value of an unrelated attribute and
surfaced wrong printer / user / job data.
"""

from oida.pcap.passive.ipp import IPPPassiveListener


class _FakeLayer:
    """Minimal stand-in for a pyshark IPP layer.

    Only exposes the ``name`` / ``charstring_value`` attributes that
    ``get_field`` reads. It deliberately has no ``_all_fields`` /
    ``all_field_names`` so ``get_all_fields`` returns ``{}`` and the
    typed-field fallback loop is a no-op, isolating the positional-pairing
    logic under test.
    """

    layer_name = "ipp"

    def __init__(self, name, charstring_value):
        self.name = name
        self.charstring_value = charstring_value


def _make_listener():
    return IPPPassiveListener(interface="lo", timeout=10)


def test_mismatched_counts_do_not_produce_wrong_pairing():
    """When name/value counts differ, no attribute is (mis)paired."""
    listener = _make_listener()
    # 4 attribute names but only 2 string values -- the classic real-packet
    # shape (integer/enum/boolean attributes interleaved with strings).
    layer = _FakeLayer(
        name=["printer-state", "copies", "printer-name", "requesting-user-name"],
        charstring_value=["MyPrinter", "alice"],
    )
    details: dict = {}
    listener._extract_attributes(layer, details)

    # The mapped string attrs must NOT be populated from the misaligned lists:
    # "printer-name" is index 2 but only 2 values exist, and even if it did the
    # value at the wrong position would be wrong. Assert no false association.
    assert "printer_name" not in details, (
        f"printer_name must not be paired from mismatched lists: {details}"
    )
    assert "requesting_user" not in details, (
        f"requesting_user must not be paired from mismatched lists: {details}"
    )
    # Specifically, the unrelated string value 'MyPrinter'/'alice' must not have
    # leaked into any mapped key.
    assert "MyPrinter" not in details.values()
    assert "alice" not in details.values()


def test_matching_counts_pair_correctly():
    """Equal-length name/value lists still pair correctly (no regression)."""
    listener = _make_listener()
    layer = _FakeLayer(
        name=["printer-name", "requesting-user-name"],
        charstring_value=["MyPrinter", "alice"],
    )
    details: dict = {}
    listener._extract_attributes(layer, details)

    assert details.get("printer_name") == "MyPrinter"
    assert details.get("requesting_user") == "alice"


def test_single_attribute_pairs():
    """A single name/value pair (no commas) still works."""
    listener = _make_listener()
    layer = _FakeLayer(name="printer-name", charstring_value="OnlyPrinter")
    details: dict = {}
    listener._extract_attributes(layer, details)
    assert details.get("printer_name") == "OnlyPrinter"
