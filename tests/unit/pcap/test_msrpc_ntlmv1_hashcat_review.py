"""Regression test for a dropped NTLMv1 hashcat format in MSRPC's NTLMSSP
extraction (src/oida/pcap/msrpc.py, ``_process_ntlmssp``, ~line 958-963).

``hashcat_str`` was only ever built when ``ntproofstr_hex`` was present --
but NTLMv1 (as opposed to NTLMv2) responses never carry an NTPROOFSTR field
at all, since NTLMv1 has no separate "proof" blob: the 24-byte NT response
itself IS the hashcat-mode-5500 response field
(``user::domain:challenge:response``). The result was that every captured
NTLMv1 Type-3 authenticate had ``hashcat_format == ""``, silently discarding
a crackable hash even though username, challenge, and nt_response were all
present.
"""

from oida.pcap.msrpc import MSRPCPassiveListener


class _Layer:
    """Minimal stand-in for a pyshark layer: attribute access only."""

    def __init__(self, **fields):
        for k, v in fields.items():
            setattr(self, k, v)


def _make_listener():
    return MSRPCPassiveListener(interface="lo", timeout=1)


SERVER_IP = "10.0.1.10"
CLIENT_IP = "10.0.1.50"
STREAM_ID = "7"
CHALLENGE_HEX = "1122334455667788"
NT_RESPONSE_HEX = "a" * 48  # 24 bytes, no ntproofstr prefix semantics for NTLMv1


def test_ntlmv1_type3_without_ntproofstr_builds_hashcat_5500_format():
    listener = _make_listener()
    listener._ntlmssp_challenges[STREAM_ID] = CHALLENGE_HEX

    type3_packet = _Layer(
        ntlmssp=_Layer(
            messagetype="0x00000003",
            **{
                "auth.domain": "CORP",
                "auth.username": "bob",
                "auth.ntresponse": NT_RESPONSE_HEX,
            },
        )
    )

    listener._process_ntlmssp(type3_packet, SERVER_IP, CLIENT_IP, STREAM_ID)

    assert len(listener._ntlmssp_auths) == 1
    entry = listener._ntlmssp_auths[-1]
    assert entry["hash_type"] == "NTLMv1"
    assert entry["ntproofstr"] == ""
    assert entry["nt_response"] == NT_RESPONSE_HEX

    expected = f"bob::CORP:{CHALLENGE_HEX}:{NT_RESPONSE_HEX}"
    assert entry["hashcat_format"] == expected
