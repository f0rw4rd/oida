"""Regression: BFD diagnostic-code table must match the registered BFD registry.

``BFD_DIAG`` in ``src/oida/pcap/bfd.py`` stopped at code 8, so a session torn
down with diagnostic 9 ("Mis-Connectivity Defect", RFC 6428 / registered in
Wireshark's ``bfd.diag`` value_string) rendered as ``Unknown(9)`` in the
operator-facing ``diag_name`` detail and the harvest column.  Codes 1 and 3
also used abbreviated text that does not match the canonical names.

Authority: ``tshark -G values | grep 'bfd.diag'`` (tshark 4.4.15) and
RFC 5880 sec. 4.1 / RFC 6428.
"""

from oida.pcap.bfd import BFDPassiveListener

# Verbatim from `tshark -G values | grep 'bfd.diag'`
TSHARK_BFD_DIAG = {
    0: "No Diagnostic",
    1: "Control Detection Time Expired",
    2: "Echo Function Failed",
    3: "Neighbor Signaled Session Down",
    4: "Forwarding Plane Reset",
    5: "Path Down",
    6: "Concatenated Path Down",
    7: "Administratively Down",
    8: "Reverse Concatenated Path Down",
    9: "Mis-Connectivity Defect",
}


def test_diag_table_matches_registry():
    assert BFDPassiveListener.BFD_DIAG == TSHARK_BFD_DIAG


def test_mis_connectivity_defect_is_named():
    """Code 9 must not fall through to Unknown(9)."""
    assert BFDPassiveListener.BFD_DIAG.get(9) == "Mis-Connectivity Defect"


def test_no_fabricated_codes():
    """No code outside the registered 0-9 range."""
    assert set(BFDPassiveListener.BFD_DIAG) == set(range(10))
