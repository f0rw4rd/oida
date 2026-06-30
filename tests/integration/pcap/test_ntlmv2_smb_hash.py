"""End-to-end hash test on a REAL captured NetNTLMv2 (SMB) handshake.

Fixture ``smb/oida_ntlmv2_smb.pcap`` was captured from a COMPLETE NTLMSSP
exchange (Type 1/2/3, server challenge present) between ``smbclient`` and an
impacket ``smbserver.py`` (see docker/capture/capture_ntlm_smb.sh). impacket also
printed the same NetNTLMv2 hash it received -> independent oracle confirmation.
Account ``oida`` / ``S3cretNt1`` (WORKGROUP).

    hashcat -m 5600 '<line>' <wordlist>   ->  S3cretNt1   (verified)

This is the project's first COMPLETE NetNTLMv2 fixture (all the older NTLM
fixtures lack the Type 2 server challenge and are therefore uncrackable).
The exact line is deterministic for this fixed pcap.
"""

import re

import pytest

from .conftest import _run_listener_test

pytestmark = [pytest.mark.integration]

EXPECTED = (
    "oida::WORKGROUP:aaaaaaaaaaaaaaaa:51884c1c9588b782aac7f6b3c309e631:"
    "0101000000000000005dc670f203dd01c932a8a459ccda8f000000000200100054004c0043004a005700"
    "4c004d0057000400100054004c0043004a0057004c004d00570001001000500058004a004e0046005a00"
    "4400530003001000500058004a004e0046005a004400530007000800005dc670f203dd01060004000200"
    "0000080030003000000000000000000000000000000055e74a985081311444939adcfc8bbc0c6a370bc2"
    "a9c44a3016691bc1559749960a0010000000000000000000000000000000000009001a00630069006600"
    "73002f006f006900640061002d0073006d00620000000000"
)


def test_ntlmv2_smb_hash_is_crackable_mode_5600():
    listener, _devices, _result = _run_listener_test(
        "ntlm",
        "NTLMPassiveListener",
        "ntlmssp",
        "smb/oida_ntlmv2_smb.pcap",
        min_devices=0,
        min_interactions=0,
    )
    hashes = listener.get_hashcat_hashes()
    assert EXPECTED in hashes, f"expected NetNTLMv2 line not found; got {hashes}"
    # Shape guard: user::domain:serverchallenge(16hex):ntproof(32hex):blob(hex)
    for h in hashes:
        m = re.fullmatch(r"([^:]+)::([^:]*):([0-9a-f]{16}):([0-9a-f]{32}):([0-9a-f]+)", h)
        assert m, f"not a valid mode-5600 NetNTLMv2 line: {h[:80]}"
