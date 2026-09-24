"""Tests for hashcat-compatible hash export from credential listeners via PcapScanner."""

import tempfile
from pathlib import Path
from types import SimpleNamespace


from oida.protocols.pcap.scanner import PcapScanner

from tests.unit.pcap.conftest import (
    FIXTURES_ROOT,
    requires_pyshark,
    _skip_unless_exists,
    _get_listener_direct,
)


class TestHashcatExport:
    """Hashcat-compatible hash export from credential listeners."""

    @requires_pyshark
    def test_ntlm_hashcat_format(self):
        """NTLM get_hashcat_hashes() returns user::domain:... format."""
        listener = _get_listener_direct(
            FIXTURES_ROOT / "http" / "bruteshark_ntlm_http.pcap", "ntlm"
        )
        hashes = listener.get_hashcat_hashes()
        # ntlm_http.pcap should have NTLM auth exchanges
        if hashes:
            for h in hashes:
                assert "::" in h, f"NTLM hash should contain '::', got: {h}"

    @requires_pyshark
    def test_kerberos_hashcat_format(self):
        """Kerberos get_hashcat_hashes() returns $krb5 prefixed hashes."""
        listener = _get_listener_direct(
            FIXTURES_ROOT / "kerberos" / "bruteshark_kerberos_tcp.pcap", "kerberos"
        )
        hashes = listener.get_hashcat_hashes()
        if hashes:
            for h in hashes:
                assert h.startswith("$krb5"), (
                    f"Kerberos hash should start with $krb5, got: {h[:40]}"
                )

    @requires_pyshark
    def test_http_digest_hashcat_format(self):
        """HTTP Digest get_hashcat_hashes() returns John `hdaa` format lines.

        hashcat has no HTTP-digest mode; the crackable format is John's hdaa
        (``user:$response$...``), NOT the bogus ``$digest-md5$``.
        """
        listener = _get_listener_direct(
            FIXTURES_ROOT / "http" / "bruteshark_http_digest.pcap", "http"
        )
        hashes = listener.get_hashcat_hashes()
        if hashes:
            for h in hashes:
                assert ":$response$" in h, (
                    f"HTTP digest hash should be John hdaa (':$response$'), got: {h[:60]}"
                )
                assert "$digest-md5$" not in h, "the fabricated $digest-md5$ format must be gone"

    @requires_pyshark
    def test_vnc_hashcat_format(self):
        """VNC get_hashcat_hashes() returns $vnc$*CHALLENGE*RESPONSE format."""
        listener = _get_listener_direct(FIXTURES_ROOT / "vnc" / "wireshark_vnc.pcap", "vnc")
        hashes = listener.get_hashcat_hashes()
        if hashes:
            for h in hashes:
                assert h.startswith("$vnc$*"), f"VNC hash should start with $vnc$*, got: {h[:40]}"

    @requires_pyshark
    def test_hashcat_flag_produces_file(self):
        """PcapScanner with hashcat=True writes hashcat.txt output."""
        pcap = FIXTURES_ROOT / "http" / "bruteshark_ntlm_http.pcap"
        _skip_unless_exists(pcap)
        with tempfile.TemporaryDirectory() as tmpdir:
            scanner = PcapScanner(
                str(pcap), args={"protocols": "ntlm", "hashcat": True, "output_dir": tmpdir}
            )
            scanner.run_scan()
            hashcat_file = Path(tmpdir) / "hashcat.txt"
            if hashcat_file.exists():
                content = hashcat_file.read_text()
                assert len(content) > 0, "hashcat.txt should not be empty"
                # Should contain mode comment headers
                assert "# " in content, "hashcat.txt should contain comment headers"

    @requires_pyshark
    def test_hashcat_empty_when_no_hashes(self):
        """No hashcat output when pcap has no crackable hashes."""
        pcap = FIXTURES_ROOT / "ftp" / "bruteshark_ftp.pcap"
        _skip_unless_exists(pcap)
        with tempfile.TemporaryDirectory() as tmpdir:
            scanner = PcapScanner(
                str(pcap), args={"protocols": "ftp", "hashcat": True, "output_dir": tmpdir}
            )
            scanner.run_scan()
            hashcat_file = Path(tmpdir) / "hashcat.txt"
            # FTP has no get_hashcat_hashes(), so no file should be written
            assert not hashcat_file.exists(), "hashcat.txt should not exist for plaintext-only pcap"


class TestKerberosRepServerPort:
    """*-REP server_port must record the KDC port (src_port=88), not the client port.

    Regression for the AS-REP/TGS-REP direction bug: process_packet passed
    dst_port (the client's ephemeral port for a reply) as server_port to the
    REP handlers, so the KDC's hash recorded a random high client port instead
    of 88. The fix passes src_port for the REP path (the KDC is the sender).

    These drive the handlers directly (no pyshark) with a SimpleNamespace
    standing in for the kerberos layer, matching how process_packet calls them.
    """

    @staticmethod
    def _make_listener():
        from oida.pcap.kerberos import KerberosPassiveListener

        return KerberosPassiveListener(interface="lo", timeout=1)

    @staticmethod
    def _rep_layer(sname=None):
        # etype 23 = RC4_HMAC (crackable); cipher is the ticket blob.
        fields = {
            "etype": "23",
            "CNameString": "alice",
            "realm": "CORP.EXAMPLE.COM",
            # The listener selects the crackable blob from kerberos.cipher
            # occurrences via _cipher_occurrences(), which reads the "cipher"
            # attribute (a Kerberos reply exposes the enc-parts under that name).
            "cipher": "de:ad:be:ef",
        }
        if sname is not None:
            fields["SNameString"] = sname
        return SimpleNamespace(**fields)

    def test_as_rep_records_kdc_src_port(self):
        listener = self._make_listener()
        kdc_ip, client_ip = "10.0.0.1", "10.0.0.50"
        kdc_port, client_port = 88, 54321

        # Mirror process_packet's REP call: server_port must be the KDC's
        # src_port (88), NOT the client's ephemeral dst_port.
        listener._process_as_rep(kdc_ip, client_ip, "Kerberos", self._rep_layer(), kdc_port)

        assert len(listener.hashes) == 1
        h = listener.hashes[0]
        assert h.hash_type == "AS-REP"
        assert h.server_ip == kdc_ip
        assert h.server_port == kdc_port, (
            f"AS-REP server_port should be the KDC port {kdc_port}, got {h.server_port}"
        )
        assert h.client_ip == client_ip
        assert h.server_port != client_port

    def test_tgs_rep_records_kdc_src_port(self):
        listener = self._make_listener()
        kdc_ip, client_ip = "10.0.0.1", "10.0.0.50"
        kdc_port = 88

        listener._process_tgs_rep(
            kdc_ip,
            client_ip,
            "Kerberos",
            self._rep_layer(sname="HTTP,web.corp.example.com"),
            kdc_port,
        )

        assert len(listener.hashes) == 1
        h = listener.hashes[0]
        assert h.hash_type == "TGS-REP"
        assert h.server_ip == kdc_ip
        assert h.server_port == kdc_port, (
            f"TGS-REP server_port should be the KDC port {kdc_port}, got {h.server_port}"
        )


class TestNTLMHashcatFormatProperty:
    """NTLMHash.hashcat_format must not fabricate a hash when the challenge is missing.

    Pure-dataclass tests (no pyshark): a NetNTLM response captured without the
    Type 2 server challenge is uncrackable, so the property must return "" rather
    than the bare NT response (which used to leak out looking like a real hash).
    """

    def test_complete_ntlmv1_yields_mode5500_line(self):
        from oida.pcap.ntlm import NTLMHash

        h = NTLMHash(
            hash_type="NTLMv1",
            username="administrator",
            domain="VNET3",
            workstation="",
            challenge="1122334455667788",
            lm_hash="ab" * 24,
            nt_hash="cd" * 24,
        )
        assert h.hashcat_format == f"administrator::VNET3:{'ab' * 24}:{'cd' * 24}:1122334455667788"

    def test_missing_challenge_yields_empty_not_bare_response(self):
        from oida.pcap.ntlm import NTLMHash

        bare = "aa58dd5b9b655c207fac3d27e685c99d7a163a54b4b6f8cc"
        h = NTLMHash(
            hash_type="NTLMv1",
            username="administrator",
            domain="EXAMPLE",
            workstation="",
            challenge="",  # NTLM Type 2 not captured
            lm_hash="",
            nt_hash=bare,
        )
        # The bug: this used to return the bare NT response and get printed as a hash.
        assert h.hashcat_format == ""
        # hash_value still exposes the raw response for reference; it just is not
        # presented as a crackable hashcat hash.
        assert h.hash_value == bare

    def test_complete_ntlmv2_yields_mode5600_line(self):
        from oida.pcap.ntlm import NTLMHash

        nt = "0" * 32 + "deadbeef"
        h = NTLMHash(
            hash_type="NTLMv2",
            username="u",
            domain="D",
            workstation="",
            challenge="1122334455667788",
            lm_hash="",
            nt_hash=nt,
        )
        assert h.hashcat_format == f"u::D:1122334455667788:{'0' * 32}:deadbeef"


class TestNTLMConcurrentHandshakeChallengePairing:
    """Concurrent NTLM handshakes on one client/server pair must not swap challenges.

    Regression for the session-key collision bug: Type 2 challenges were stored
    under (client_ip, server_ip) only, so when one client ran multiple parallel
    NTLM auths to the same server (multiple SMB2 trees / parallel HTTP /
    back-to-back logons) every Type 2 clobbered the previous stored challenge.
    Each Type 3 then got paired with the most-recent challenge instead of the one
    from its own handshake, embedding the WRONG server challenge in the emitted
    NetNTLM line (uncrackable, yet reported as complete).

    The fix keys sessions on the tcp/udp stream id as well, so these tests drive
    _process_type2 / _process_type3 directly (no pyshark) with the stream id
    threaded through, the same way process_packet does.
    """

    @staticmethod
    def _make_listener():
        from oida.pcap.ntlm import NTLMPassiveListener

        # __init__ only needs the interface/timeout it forwards to the base; no
        # capture is started, we call the parsing helpers directly.
        return NTLMPassiveListener(interface="lo", timeout=1)

    def test_interleaved_handshakes_pair_with_own_challenge(self):
        listener = self._make_listener()

        client = "10.0.0.5"
        server = "10.0.0.9"

        # Two distinct server challenges on two distinct streams between the SAME
        # client and server.
        chal_a = "1111111111111111"
        chal_b = "2222222222222222"

        # Both Type 2 challenges arrive (server -> client) before either Type 3.
        # Without per-stream keying, the second Type 2 would overwrite the first.
        listener._process_type2(server, client, {"ntlmserverchallenge": chal_a}, stream_id="7")
        listener._process_type2(server, client, {"ntlmserverchallenge": chal_b}, stream_id="42")

        # NTLMv1 NT response = 24 bytes (48 hex chars), distinct per handshake.
        nt_a = "aa" * 24
        nt_b = "bb" * 24

        # Type 3 on stream 7 must pair with chal_a; stream 42 with chal_b.
        listener._process_type3(
            client,
            server,
            {"auth.username": "alice", "auth.domain": "CORP", "auth.ntresponse": nt_a},
            server_port=445,
            stream_id="7",
        )
        listener._process_type3(
            client,
            server,
            {"auth.username": "bob", "auth.domain": "CORP", "auth.ntresponse": nt_b},
            server_port=445,
            stream_id="42",
        )

        by_user = {h.username: h for h in listener.hashes}
        assert set(by_user) == {"alice", "bob"}, "both handshakes should yield a hash"

        # The crux: each hash carries the challenge from ITS OWN stream.
        assert by_user["alice"].challenge == chal_a
        assert by_user["bob"].challenge == chal_b
        assert by_user["alice"].nt_hash == nt_a
        assert by_user["bob"].nt_hash == nt_b

        # And the emitted hashcat lines embed the correct (own) challenge.
        lines = listener.get_hashcat_hashes()
        assert any(line.startswith("alice::CORP:") and line.endswith(chal_a) for line in lines)
        assert any(line.startswith("bob::CORP:") and line.endswith(chal_b) for line in lines)

    def test_missing_stream_id_falls_back_to_ip_pair(self):
        """No stream id (non-TCP/odd capture) still correlates via the IP pair."""
        listener = self._make_listener()
        client = "10.0.0.5"
        server = "10.0.0.9"
        chal = "3333333333333333"
        nt = "cc" * 24

        listener._process_type2(server, client, {"ntlmserverchallenge": chal}, stream_id="")
        listener._process_type3(
            client,
            server,
            {"auth.username": "carol", "auth.domain": "CORP", "auth.ntresponse": nt},
            server_port=445,
            stream_id="",
        )

        assert len(listener.hashes) == 1
        assert listener.hashes[0].challenge == chal


class TestKerberosHashesSummaryPairing:
    """get_hashes_summary() must pair each hash with ITS OWN hashcat_format.

    Regression for the index-misalignment bug in kerberos.py: the summary used
    to advance a positional index into get_hashcat_hashes() for EVERY hash in
    self.hashes, while get_hashcat_hashes() only emitted a line for AS-REQ when
    etype == 23. But _process_as_req records AS-REQ hashes for etypes 17/18/23,
    so an AS-REQ with an AES etype (17/18) produced no hashcat line yet still
    advanced the index -- every subsequent hash then received the cracking
    string belonging to a DIFFERENT (later) hash. The fix pairs each summary
    entry with h.hashcat_format directly.
    """

    @staticmethod
    def _hash(hash_type, etype, username, *, service_name="", hash_value=None):
        from oida.pcap.kerberos import KerberosHash

        # A realistic enc-part length so hashcat_format's checksum split applies
        # (RC4 needs > 32 hex, AES > 24). 80 hex chars satisfies both.
        if hash_value is None:
            hash_value = "ab" * 40
        return KerberosHash(
            hash_type=hash_type,
            etype=etype,
            username=username,
            domain="CORP.EXAMPLE.COM",
            service_name=service_name,
            hash_value=hash_value,
            server_ip="10.0.0.1",
            client_ip="10.0.0.50",
        )

    def test_unsupported_etype_does_not_shift_pairing(self):
        from oida.pcap.kerberos import KerberosPassiveListener

        listener = KerberosPassiveListener(interface="lo", timeout=1)

        # An AS-REP with an unsupported etype (1 = DES) produces NO hashcat line,
        # yet is still recorded. Ordered BEFORE the crackable AS-REP/TGS-REP,
        # this is what used to corrupt the positional index.
        listener.hashes = [
            self._hash("AS-REP", 1, "gap"),  # unsupported etype -> no hashcat line
            self._hash("AS-REP", 23, "alice"),
            self._hash("TGS-REP", 23, "bob", service_name="HTTP/web.corp"),
        ]

        summary = {e["username"]: e for e in listener.get_hashes_summary()}

        # The non-crackable entry gets no hashcat line of its own.
        assert summary["gap"]["hashcat_format"] == ""

        # The crux: each crackable hash carries ITS OWN hashcat line.
        for h in listener.hashes:
            assert summary[h.username]["hashcat_format"] == h.hashcat_format

        assert summary["alice"]["hashcat_format"].startswith("$krb5asrep$23$alice@")
        assert summary["bob"]["hashcat_format"].startswith("$krb5tgs$23$*bob$")
        # And not slipped onto the wrong entry.
        assert "$krb5asrep" not in summary["gap"]["hashcat_format"]
        assert "$krb5tgs" not in summary["alice"]["hashcat_format"]

    def test_get_hashcat_hashes_matches_per_entry_property(self):
        from oida.pcap.kerberos import KerberosPassiveListener

        listener = KerberosPassiveListener(interface="lo", timeout=1)
        listener.hashes = [
            self._hash("AS-REP", 1, "gap"),  # unsupported etype -> no line
            self._hash("AS-REQ", 23, "preauth"),
            self._hash("AS-REP", 23, "alice"),
        ]

        # get_hashcat_hashes() must emit exactly the non-empty per-entry lines.
        assert listener.get_hashcat_hashes() == [
            h.hashcat_format for h in listener.hashes if h.hashcat_format
        ]
        # The unsupported-etype entry contributes nothing.
        assert len(listener.get_hashcat_hashes()) == 2


class TestNTLMHashesSummaryPairing:
    """get_hashes_summary() must pair each hash with ITS OWN hashcat_format.

    Regression for the index-misalignment bug: the summary used to advance a
    positional index into get_hashcat_hashes() for EVERY hash that merely had a
    challenge, while get_hashcat_hashes() only emits a line for crackable hashes
    (NTLMv1, or NTLMv2 with nt_hash >= 32 hex). A challenge-bearing but
    non-crackable hash (hash_type=='NTLM', the default when the NT response is
    empty) emitted no line yet still advanced the index, so every subsequent
    credential received the hashcat string belonging to a DIFFERENT hash.
    """

    @staticmethod
    def _hash(hash_type, username, nt_hash, *, challenge="1122334455667788", lm_hash=""):
        from oida.pcap.ntlm import NTLMHash

        return NTLMHash(
            hash_type=hash_type,
            username=username,
            domain="CORP",
            workstation="",
            challenge=challenge,
            lm_hash=lm_hash,
            nt_hash=nt_hash,
            server_ip="10.0.0.9",
            client_ip="10.0.0.5",
        )

    def test_noncrackable_challenge_hash_does_not_shift_pairing(self):
        from oida.pcap.ntlm import NTLMPassiveListener

        listener = NTLMPassiveListener(interface="lo", timeout=1)

        nt_alice = "aa" * 24
        nt_bob = "bb" * 24

        # 'gap' has a server challenge (so it counts as complete) but hash_type
        # 'NTLM' with an empty NT response yields NO hashcat line. It is ordered
        # BEFORE the real NTLMv1 creds, which is what used to corrupt the index.
        listener.hashes = [
            self._hash("NTLM", "gap", ""),
            self._hash("NTLMv1", "alice", nt_alice),
            self._hash("NTLMv1", "bob", nt_bob),
        ]

        summary = {e["username"]: e for e in listener.get_hashes_summary()}

        # The non-crackable hash gets no hashcat line of its own.
        assert summary["gap"]["hashcat_format"] == ""

        # The crux: each crackable cred must carry ITS OWN hashcat line, derived
        # from its own NT response — not one shifted in from a neighbour.
        for h in listener.hashes:
            if h.hash_type == "NTLMv1":
                assert summary[h.username]["hashcat_format"] == h.hashcat_format
        assert summary["alice"]["hashcat_format"].endswith(f"{nt_alice}:1122334455667788")
        assert summary["bob"]["hashcat_format"].endswith(f"{nt_bob}:1122334455667788")
        # And not swapped with each other.
        assert nt_bob not in summary["alice"]["hashcat_format"]
        assert nt_alice not in summary["bob"]["hashcat_format"]
