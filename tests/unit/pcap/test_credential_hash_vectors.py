"""Known-answer tests for non-Kerberos credential hash formats.

Each expected line is checked against the authoritative source:
  - hashcat example_hashes wiki (modes 11100 PostgreSQL, 11200 MySQL,
    4800 iSCSI CHAP): https://hashcat.net/wiki/doku.php?id=example_hashes
  - John the Ripper HDAA_README (HTTP Digest, `hdaa`) and vncpcap2john (VNC).

These pin the signature, separators, field order, and any prefix-stripping
that the per-credential ``hashcat_format`` property must perform — the things
the format audit found wrong (PostgreSQL `:`-separated/no-signature, HTTP's
fabricated `$digest-md5$`, VNC mislabeled as hashcat 5600).
"""


# --- PostgreSQL CRAM (MD5) — hashcat mode 11100 ------------------------------
# Canonical: $postgres$postgres*f0784ea5*2091bb7d4725d1ca85e8de6ec349baf6


def _pg_cred(**kw):
    from oida.pcap.pgsql import PostgreSQLCredential

    base = dict(
        username="postgres",
        database="postgres",
        password_or_hash="md52091bb7d4725d1ca85e8de6ec349baf6",
        salt="f0784ea5",
        auth_type="md5",
        server_ip="10.0.0.1",
        client_ip="10.0.0.50",
        success=None,
    )
    base.update(kw)
    return PostgreSQLCredential(**base)


def test_postgres_11100_known_answer():
    h = _pg_cred()
    assert h.hashcat_format == "$postgres$postgres*f0784ea5*2091bb7d4725d1ca85e8de6ec349baf6"


def test_postgres_strips_md5_prefix_and_colon_salt():
    # Wire value carries the "md5" prefix; salt may arrive colon-hex in EK mode.
    h = _pg_cred(password_or_hash="md5" + "ab" * 16, salt="f0:78:4e:a5")
    assert h.hashcat_format == f"$postgres$postgres*f0784ea5*{'ab' * 16}"


def test_postgres_no_salt_yields_empty():
    h = _pg_cred(salt="")
    assert h.hashcat_format == ""


# --- HTTP Digest — John the Ripper `hdaa` ------------------------------------
# Canonical (HDAA_README):
# user:$response$679066476e67b5c7c4e88f04be567f8b$user$myrealm$GET$/$
#   8c12bd8f728afe56d45a0ce846b70e5a$00000001$4b61913cec32e2c9$auth


def _http_cred(**kw):
    from oida.pcap.http import HTTPCredential

    base = dict(
        auth_type="Digest",
        credential_type="hash",
        username="user",
        realm="myrealm",
        method="GET",
        uri="/",
        nonce="8c12bd8f728afe56d45a0ce846b70e5a",
        nc="00000001",
        cnonce="4b61913cec32e2c9",
        qop="auth",
        response="679066476e67b5c7c4e88f04be567f8b",
    )
    base.update(kw)
    return HTTPCredential(**base)


def test_http_digest_hdaa_known_answer():
    expected = (
        "user:$response$679066476e67b5c7c4e88f04be567f8b$user$myrealm$GET$/$"
        "8c12bd8f728afe56d45a0ce846b70e5a$00000001$4b61913cec32e2c9$auth"
    )
    assert _http_cred().hashcat_format == expected


def test_http_digest_no_fabricated_signature():
    line = _http_cred().hashcat_format
    assert "$digest-md5$" not in line
    assert line.startswith("user:$response$")


def test_http_digest_missing_response_yields_empty():
    assert _http_cred(response="").hashcat_format == ""


# --- VNC — John the Ripper `vnc` ---------------------------------------------
# vncpcap2john line body: $vnc$*<challenge>*<response>


def _vnc_cred(**kw):
    from oida.pcap.vnc import VNCCredential

    base = dict(
        challenge="894443629f4a9675809cff5da2e84651",
        response="271d94eb610b5c42588dc53506419e6a",
        server_ip="10.0.0.1",
        client_ip="10.0.0.50",
        server_port=5900,
    )
    base.update(kw)
    return VNCCredential(**base)


def test_vnc_john_known_answer():
    h = _vnc_cred()
    assert h.hashcat_format == (
        "$vnc$*894443629f4a9675809cff5da2e84651*271d94eb610b5c42588dc53506419e6a"
    )


def test_vnc_incomplete_pair_yields_empty():
    assert _vnc_cred(response="").hashcat_format == ""
    assert _vnc_cred(challenge="").hashcat_format == ""


# --- SIP digest — hashcat mode 11400 (14-field layout) -----------------------
# Canonical (hashcat example_hashes 11400):
# $sip$*192.168.100.100*192.168.100.121*username*asterisk*REGISTER*sip*
#   192.168.100.121**2b01df0b***MD5*ad0520061ca07c120d7e8ce696a6df2d


def _sip_cred(**kw):
    from oida.pcap.sip import SIPDigestCredential

    base = dict(
        username="username",
        realm="asterisk",
        nonce="2b01df0b",
        uri="sip:192.168.100.121",
        response="ad0520061ca07c120d7e8ce696a6df2d",
        qop="",
        nc="",
        cnonce="",
        algorithm="MD5",
        method="REGISTER",
        server_ip="192.168.100.100",
        client_ip="192.168.100.121",
    )
    base.update(kw)
    return SIPDigestCredential(**base)


def test_sip_11400_known_answer():
    expected = (
        "$sip$*192.168.100.100*192.168.100.121*username*asterisk*REGISTER*sip*"
        "192.168.100.121**2b01df0b***MD5*ad0520061ca07c120d7e8ce696a6df2d"
    )
    assert _sip_cred().hashcat_format == expected


def test_sip_field_count_depends_on_qop():
    # RFC2069 (no qop): qop field is OMITTED -> 13 fields (12 separators).
    noqop = _sip_cred().hashcat_format[len("$sip$*") :]
    assert noqop.count("*") == 12
    # qop=auth: qop field present -> 14 fields (13 separators).
    withqop = _sip_cred(qop="auth", nc="00000001", cnonce="deadbeef").hashcat_format[
        len("$sip$*") :
    ]
    assert withqop.count("*") == 13


def test_sip_qop_auth_fields_present():
    h = _sip_cred(qop="auth", nc="00000001", cnonce="deadbeef").hashcat_format
    # qop/nc/cnonce land in their dedicated slots (tokens 10/11/12).
    assert "*deadbeef*00000001*auth*MD5*" in h


def test_sip_missing_response_yields_empty():
    assert _sip_cred(response="").hashcat_format == ""


# --- CRAM-MD5 — hashcat mode 10200 (SMTP/IMAP) -------------------------------
# Canonical (hashcat example_hashes 10200), cracks to "hashcat":
#   $cram_md5$PG5vLXJlcGx5QGhhc2hjYXQubmV0Pg==$dXNlciA0NGVhZmQyMmZlNzY2NzBmNmIyODc5MDgxYTdmNWY3MQ==
CRAM_CHAL = "PG5vLXJlcGx5QGhhc2hjYXQubmV0Pg=="
CRAM_RESP = "dXNlciA0NGVhZmQyMmZlNzY2NzBmNmIyODc5MDgxYTdmNWY3MQ=="
CRAM_EXPECT = f"$cram_md5${CRAM_CHAL}${CRAM_RESP}"


def test_imap_cram_md5_10200_known_answer():
    from oida.pcap.imap import IMAPCredential

    c = IMAPCredential(
        auth_method="CRAM-MD5",
        credential_type="hash",
        username="user",
        hash_value=CRAM_RESP,
        challenge=CRAM_CHAL,
    )
    assert c.hashcat_format == CRAM_EXPECT


def test_smtp_cram_md5_10200_known_answer():
    from oida.pcap.smtp import SMTPCredential

    c = SMTPCredential(
        auth_method="CRAM-MD5",
        credential_type="hash",
        username="user",
        hash_value=CRAM_RESP,
        challenge=CRAM_CHAL,
    )
    assert c.hashcat_format == CRAM_EXPECT


def test_cram_md5_plaintext_yields_empty():
    from oida.pcap.imap import IMAPCredential

    c = IMAPCredential(auth_method="LOGIN", credential_type="plaintext", username="u", password="p")
    assert c.hashcat_format == ""


# --- iSCSI CHAP — hashcat mode 4800 ------------------------------------------
# Canonical (hashcat example_hashes 4800): hash:challenge:id


def test_iscsi_chap_4800_known_answer():
    from oida.pcap.iscsi import ISCSICredential

    c = ISCSICredential(
        username="iscsiuser",
        response="afd09efdd6f8ca9f18ec77c5869788c3",
        challenge="01020304050607080910111213141516",
        chap_id="01",
        server_ip="10.0.0.1",
        client_ip="10.0.0.2",
    )
    assert c.hashcat_format == (
        "afd09efdd6f8ca9f18ec77c5869788c3:01020304050607080910111213141516:01"
    )


# --- VRRP / BFD — no cracking format exists; must NOT present a deliverable hash


def test_vrrp_md5_is_not_a_crackable_hash():
    from oida.pcap.vrrp import VRRPCredential

    c = VRRPCredential(
        auth_type=254,
        auth_type_name="MD5",
        auth_string="VRID1@10.0.0.1",
        credential_type="hash",
        md5_hash="deadbeef" * 4,
    )
    # The digest stays available for forensics, but no crackable line is offered.
    assert c.hash_value == "deadbeef" * 4
    assert c.hashcat_format == ""


def test_bfd_keyed_digest_is_not_a_crackable_hash():
    from oida.pcap.bfd import BFDCredential

    c = BFDCredential(
        auth_type=2,
        auth_type_name="Keyed MD5",
        credential_type="hash",
        password="deadbeef" * 4,
    )
    assert c.hashcat_format == ""
