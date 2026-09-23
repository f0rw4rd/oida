"""Shared supervision-frame handling for the HSR and PRP passive listeners.

HSR and PRP (IEC 62439-3) share the ``hsr_prp_supervision`` tshark dissector for
their supervision frames, and both listeners track nodes with dataclasses
(``HSRNode`` / ``PRPNode``) that expose the same core fields --
``node_type``, ``redbox_mac``, ``vdan_macs``, ``supervision_count``,
``total_frames``. This module centralizes the supervision-field extraction and
node-bookkeeping logic that was previously copy-pasted identically between
``hsr.py`` and ``prp.py``. Node-type *classification* (the DANH/DANP default)
stays per-listener since the fallback differs between the two protocols.
"""

from __future__ import annotations

from typing import Any, Callable, Set, Tuple


def extract_supervision_fields(
    get_field: Callable[..., Any], sup_layer: Any
) -> Tuple[str, str, str, str]:
    """Pull the shared TLV fields off an ``hsr_prp_supervision`` layer.

    Returns ``(sup_src_mac_a, sup_src_mac_b, redbox_mac, vdan_mac)``.
    """
    sup_src_mac_a = str(get_field(sup_layer, "source_mac_address_A") or "")
    sup_src_mac_b = str(get_field(sup_layer, "source_mac_address_B") or "")
    redbox_mac = str(get_field(sup_layer, "red_box_mac_address") or "")
    vdan_mac = str(get_field(sup_layer, "vdan_mac_address") or "")
    return sup_src_mac_a, sup_src_mac_b, redbox_mac, vdan_mac


def update_supervision_node(
    node: Any,
    known_macs: Set[str],
    node_mac: str,
    node_type: str,
    redbox_mac: str,
    vdan_mac: str,
) -> None:
    """Apply the shared supervision-frame bookkeeping to an HSR/PRP node.

    Mutates *node* (an ``HSRNode``/``PRPNode``) and *known_macs* in place;
    both dataclasses expose the same ``node_type`` / ``redbox_mac`` /
    ``vdan_macs`` / ``supervision_count`` / ``total_frames`` shape.
    """
    node.supervision_count += 1
    node.total_frames += 1
    if node_type:
        node.node_type = node_type
    if redbox_mac:
        node.redbox_mac = redbox_mac
    if vdan_mac:
        node.vdan_macs.add(vdan_mac)

    known_macs.add(node_mac)
    if redbox_mac:
        known_macs.add(redbox_mac)
    if vdan_mac:
        known_macs.add(vdan_mac)
