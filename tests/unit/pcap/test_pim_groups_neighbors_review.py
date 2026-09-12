"""Regression tests for PIM Join/Prune group extraction and neighbor tracking.

Two defects, recorded as untriaged leads after a review wave died:

1. ``_field_to_list`` only splits Python-list *reprs* (``"['a', 'b']"``), but
   ``PySharkListenerBase.get_field`` returns EK-mode multi-value fields as a
   comma-joined plain string (``"239.1.1.1,239.2.2.2"`` -- see pyshark_base
   ``",".join(parts)``). The Join/Prune handler therefore recorded ONE bogus
   merged group instead of two, in both the device's ``multicast_groups`` and
   the global group table. The Hello ``address_list`` path right above it
   splits on "," -- the two paths were inconsistent.

2. The per-device ``neighbors`` list is initialized empty and nothing ever
   appends to it, so the "update neighbors if new ones found" merge block and
   the advertised neighbor tracking were dead code. The one neighbor-address
   signal PIM exposes per message is the Join/Prune upstream neighbor.
"""

from oida.pcap.pim import PIMPassiveListener, _field_to_list


class _Pim:
    def __init__(self, **fields):
        self._layer_name = "pim"
        for key, value in fields.items():
            setattr(self, key, value)

    def get_field_value(self, name, raw=False):
        return getattr(self, name.replace(".", "_"), None)


class _Packet:
    def __init__(self, pim):
        self.pim = pim
        self.ip = _Pim(src="10.0.0.1", dst="224.0.0.13")
        self.eth = _Pim(src="00:11:22:33:44:55", dst="01:00:5e:00:00:0d")

    def __contains__(self, item):
        return item in ("eth", "ip", "pim")


def _listener():
    return PIMPassiveListener(interface="lo", timeout=1)


def _join_prune(**extra):
    return _Packet(
        _Pim(
            version="2",
            type="3",
            numgroups="2",
            numjoins="2",
            numprunes="0",
            upstream_neighbor="10.9.9.9",
            holdtime="210",
            **extra,
        )
    )


# ---------------------------------------------------------------------------
# 1. comma-joined multi-value groups
# ---------------------------------------------------------------------------


def test_ek_comma_joined_groups_split_into_separate_entries():
    listener = _listener()
    listener.process_packet(_join_prune(group="239.1.1.1,239.2.2.2"))
    groups = sorted(listener.multicast_groups.keys())
    assert groups == ["239.1.1.1", "239.2.2.2"]


def test_ek_comma_joined_ipv6_groups_split_into_separate_entries():
    listener = _listener()
    listener.process_packet(_join_prune(group_ip6="ff15::1,ff15::2"))
    groups = sorted(listener.multicast_groups.keys())
    assert groups == ["ff15::1", "ff15::2"]


def test_scalar_group_still_works():
    listener = _listener()
    listener.process_packet(_join_prune(group="239.1.1.1"))
    assert list(listener.multicast_groups.keys()) == ["239.1.1.1"]


def test_list_repr_still_works():
    assert _field_to_list("['239.1.1.1', '239.2.2.2']") == ["239.1.1.1", "239.2.2.2"]


def test_device_multicast_groups_are_split_too():
    listener = _listener()
    listener.process_packet(_join_prune(group="239.1.1.1,239.2.2.2"))
    dev = listener.discovered_devices["pim:10.0.0.1"]
    assert sorted(dev.pim_data["multicast_groups"]) == ["239.1.1.1", "239.2.2.2"]


# ---------------------------------------------------------------------------
# 2. neighbors
# ---------------------------------------------------------------------------


def test_join_prune_upstream_neighbor_lands_in_device_neighbors():
    listener = _listener()
    listener.process_packet(_join_prune(group="239.1.1.1"))
    dev = listener.discovered_devices["pim:10.0.0.1"]
    assert "10.9.9.9" in dev.pim_data["neighbors"]


def test_neighbors_merge_is_idempotent():
    listener = _listener()
    listener.process_packet(_join_prune(group="239.1.1.1"))
    listener.process_packet(_join_prune(group="239.1.1.1"))
    dev = listener.discovered_devices["pim:10.0.0.1"]
    assert dev.pim_data["neighbors"] == ["10.9.9.9"]
