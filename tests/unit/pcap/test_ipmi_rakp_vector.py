"""Known-answer test for IPMI 2.0 RAKP hashcat mode-7300 salt assembly.

Canonical vector (hashcat example_hashes, mode 7300):
  salt = b7c2d6f13a43dce2e44ad120a9cd8a13d0ca23f0414275c0bbe1070d2d1299b1
         c04da0f1a0f1e4e2537300263a2200000000000000000000140768617368636174
  hmac = 472bdabe2d5d4bffd6add7b3ba79a291d104a9ef

The salt is the exact HMAC message the BMC signs:
  SIDm(4) ‖ SIDc(4) ‖ Rm(16) ‖ Rc(16) ‖ GUIDc(16) ‖ RoleM(1) ‖ ULengthM(1) ‖ UNameM

This test reconstructs the on-wire RAKP-1 and RAKP-2 message bodies from those
components, feeds them through the listener's parsers + salt builder, and asserts
the reassembled ``salt:hmac`` equals the canonical line — pinning the field
offsets AND the salt field ORDER (the parts that were previously discarded).
"""

from types import SimpleNamespace

from oida.pcap.ipmi import IPMICredential, IPMIPassiveListener

SALT = (
    "b7c2d6f13a43dce2e44ad120a9cd8a13d0ca23f0414275c0bbe1070d2d1299b1"
    "c04da0f1a0f1e4e2537300263a2200000000000000000000140768617368636174"
)
HMAC = "472bdabe2d5d4bffd6add7b3ba79a291d104a9ef"

# Decompose the canonical salt into its IPMI fields.
_s = bytes.fromhex(SALT)
SIDm, SIDc, Rm, Rc = _s[0:4], _s[4:8], _s[8:24], _s[24:40]
GUIDc, RoleM, ULen, UName = _s[40:56], _s[56:57], _s[57:58], _s[58:]


def _pkt(body: bytes):
    """Minimal stand-in for a pyshark packet carrying a raw RAKP body."""
    return SimpleNamespace(data=SimpleNamespace(data=body))


def _rakp1_body() -> bytes:
    # [0]tag [1:4]reserved [4:8]SIDc [8:24]Rm [24]Role [25:27]reserved [27]ULen [28:]UName
    return b"\x00" + b"\x00\x00\x00" + SIDc + Rm + RoleM + b"\x00\x00" + ULen + UName


def _rakp2_body() -> bytes:
    # [0]tag [1:4]status/reserved [4:8]SIDm [8:24]Rc [24:40]GUID [40:]HMAC
    return b"\x00" + b"\x00\x00\x00" + SIDm + Rc + GUIDc + bytes.fromhex(HMAC)


def test_rakp_salt_assembly_matches_7300_vector():
    listener = IPMIPassiveListener(interface="lo", timeout=1)
    r1 = listener._parse_rakp1(_pkt(_rakp1_body()))
    r2 = listener._parse_rakp2(_pkt(_rakp2_body()))

    assert r1["username"] == "hashcat"
    assert r2["hmac"] == HMAC

    salt = listener._build_rakp_salt(r1, r2)
    assert salt == SALT, f"reassembled salt != canonical\n got {salt}\n exp {SALT}"

    cred = IPMICredential(
        username="hashcat",
        credential_type="rakp_hash",
        source_ip="10.0.0.5",
        dest_ip="10.0.0.9",
        rakp_hash=HMAC,
        rakp_salt=salt,
    )
    assert cred.hashcat_format == f"{SALT}:{HMAC}"


def test_rakp_no_salt_without_rakp1():
    # RAKP-2 captured but RAKP-1 missing -> no salt -> not a deliverable hash.
    cred = IPMICredential(
        username="",
        credential_type="rakp_hash",
        source_ip="10.0.0.5",
        dest_ip="10.0.0.9",
        rakp_hash=HMAC,
        rakp_salt="",
    )
    assert cred.hashcat_format == ""
