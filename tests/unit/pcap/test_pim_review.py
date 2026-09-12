"""Regression tests for src/oida/pcap/pim.py found during the shared/ bug hunt.

Two confirmed defects:

1. ``_field_to_list`` only split *bracketed* list reprs (``"['a', 'b']"``). But the
   production capture path uses ``use_ek=True``, where a repeated tshark field comes
   back from pyshark as a native list, and ``PassiveListenerBase.get_field()`` joins
   list values with ``","`` into a plain, unbracketed string. So multiple multicast
   groups in one Join/Prune collapsed into ONE bogus entry, e.g.
   ``['ff05::9999,ff05::9999']``. The sibling ``address_list`` handling at pim.py:213
   already does ``.split(",")``, and the ``addr_address_family`` handling at pim.py:251
   already handles both forms -- ``_field_to_list`` was the odd one out.

2. The ``neighbors`` list built in ``process_packet`` was never appended to, so
   the merge loop in ``_update_device`` was dead code and every device reported
   ``neighbors: []``. The Join/Prune branch already extracts a genuine PIM neighbour
   identity (``pim.upstream_neighbor`` / ``pim.upstream_neighbor_ip6``) but only
   stored it in ``extra_details``.
"""

import pytest

from oida.pcap.pim import _field_to_list


class TestFieldToList:
    """_field_to_list must handle every shape get_field() can produce."""

    def test_plain_comma_joined_string_is_split(self):
        """EK mode: get_field() joins a repeated field's values with ','."""
        assert _field_to_list("ff05::9999,ff05::1234") == ["ff05::9999", "ff05::1234"]

    def test_duplicate_groups_are_not_concatenated(self):
        """The exact shape seen in wireshark_pim_register.cap."""
        assert _field_to_list("ff05::9999,ff05::9999") == ["ff05::9999", "ff05::9999"]

    def test_ipv4_comma_joined(self):
        assert _field_to_list("239.1.1.1,239.2.2.2,239.3.3.3") == [
            "239.1.1.1",
            "239.2.2.2",
            "239.3.3.3",
        ]

    def test_bracketed_repr_still_works(self):
        assert _field_to_list("['239.1.1.1', '239.2.2.2']") == ["239.1.1.1", "239.2.2.2"]

    def test_native_list_still_works(self):
        assert _field_to_list(["239.1.1.1", "239.2.2.2"]) == ["239.1.1.1", "239.2.2.2"]

    def test_scalar_is_a_single_entry(self):
        assert _field_to_list("239.1.1.1") == ["239.1.1.1"]

    def test_empty_is_empty(self):
        assert _field_to_list("") == []

    def test_whitespace_and_empty_items_are_dropped(self):
        assert _field_to_list("239.1.1.1, ,239.2.2.2,") == ["239.1.1.1", "239.2.2.2"]


class TestNeighborsAreRecorded:
    """The `neighbors` merge in _update_device must not be dead code.

    A PIM Join/Prune names its upstream neighbour (pim.upstream_neighbor /
    pim.upstream_neighbor_ip6). That is a genuine PIM neighbour identity and must
    reach ProtocolDevice.pim_data["neighbors"], otherwise the merge loop in
    _update_device can never run.
    """

    def test_upstream_neighbor_is_appended_in_source(self):
        """Guard against the regression where `neighbors` was never populated."""
        import inspect

        from oida.pcap.pim import PIMPassiveListener

        src = inspect.getsource(PIMPassiveListener.process_packet)
        assert "neighbors.append(" in src, (
            "process_packet no longer populates `neighbors`; the merge loop in "
            "_update_device is dead code again"
        )


@pytest.mark.skipif(
    __import__("shutil").which("tshark") is None, reason="tshark not installed"
)
class TestAgainstRealCapture:
    """End-to-end against the checked-in PIM capture (EK mode = production path)."""

    def test_register_capture_groups_are_not_concatenated(self):
        import os

        pyshark = pytest.importorskip("pyshark")
        from oida.pcap.pim import PIMPassiveListener

        root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        cap_path = os.path.join(root, "fixtures", "pcap", "pim", "wireshark_pim_register.cap")
        if not os.path.exists(cap_path):
            pytest.skip("fixture missing")

        listener = PIMPassiveListener(interface="lo")
        cap = pyshark.FileCapture(cap_path, display_filter="pim", use_ek=True)
        try:
            listener.feed_packets(cap)
        finally:
            cap.close()

        for device in listener.discovered_devices.values():
            for group in device.pim_data.get("multicast_groups", []):
                assert "," not in group, f"concatenated group: {group!r}"
