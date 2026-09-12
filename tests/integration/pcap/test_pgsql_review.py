"""Regression tests for a security review of src/oida/pcap/pgsql.py.

Three findings were investigated:

FINDING 1 (HIGH, REFUTED against installed tshark): claimed that a
SCRAM-SHA-256 ``SASLInitialResponse`` is dissected by tshark as
``pgsql.type == "Password message"`` with ``pgsql.password`` holding the
literal mechanism name ``"SCRAM-SHA-256"``, causing the listener to harvest
that string as a fake credential secret. Reproduced with a synthetic
SASL/SCRAM handshake pcap (scapy-crafted raw PostgreSQL wire bytes, since no
fixture with a SCRAM login exists in tests/fixtures/pcap/pgsql/). Against the
installed tshark (4.4.15), the dissector emits *distinct* message types --
``"SASLInitialResponse message"`` / ``"SASLResponse message"`` -- and never
populates ``pgsql.password`` for these frames (the mechanism name lives in
``pgsql.auth.sasl.mech`` instead, in both EK and XML pyshark modes). Because
``_dispatch_message`` only routes ``msg_type_str == "Password message"`` to
``_handle_password``, SASL frames fall through to the generic "other message
types" branch and are never treated as a credential. No fake
"SCRAM-SHA-256" secret is harvested. This finding does not reproduce and no
fix was applied for it.

FINDING 2 (MED-HIGH, REFUTED): claimed a post-authentication ERROR/FATAL
response (e.g. an ordinary SQL syntax error) gets attributed back to the
session's still-set password_or_hash and flips an already-successful
credential's ``success`` flag to False. Reproduced by driving
``_handle_password`` -> ``_handle_auth_request_msg`` (AuthenticationOk) ->
``_handle_error_notice`` (post-auth ErrorResponse) directly. The existing
guard in ``_handle_error_notice`` (``and cred.success is None``) already
restricts the "mark as failed" branch to credentials whose success is still
unknown; a credential that has already been marked ``success=True`` is left
untouched. This finding does not reproduce and no fix was applied for it.

FINDING 3 (MED-LOW, CONFIRMED and FIXED): when ``pgsql.password`` is absent,
``_handle_password`` substituted the placeholder string ``"?"`` for
``session.password_or_hash`` and still called ``_record_credential()``,
harvesting a bogus credential whose "secret" is the literal string ``"?"``.
Fixed at ``src/oida/pcap/pgsql.py`` (``_handle_password``): the placeholder
is no longer synthesized (``password_or_hash`` is left empty), and
``_record_credential()`` is now gated on ``session.password_or_hash`` being
truthy -- matching the "if session.username and session.password:" style
guard used elsewhere in this codebase (see ftp.py, pop3.py, telnet.py).
"""

import pytest
from scapy.all import IP, TCP, Raw, wrpcap

from .conftest import _ek_mode_available, _skip_unless_pyshark

pytestmark = [pytest.mark.integration]


# ---------------------------------------------------------------------------
# Lightweight layer stub (same convention as
# tests/unit/pcap/test_pgsql_sasl_mechanism.py) for driving handlers directly
# without needing a real pyshark/tshark dissection.
# ---------------------------------------------------------------------------


class _Layer:
    """Minimal stand-in for a pyshark layer: attribute access only."""

    def __init__(self, **fields):
        for k, v in fields.items():
            setattr(self, k, v)


def _make_listener():
    from oida.pcap.pgsql import PostgreSQLPassiveListener

    return PostgreSQLPassiveListener(interface="lo", timeout=1)


CLIENT_IP = "10.0.0.5"
SERVER_IP = "10.0.0.10"
CLIENT_PORT = 54321
SERVER_PORT = 5432
NOW = "2026-01-01T00:00:00"


# ---------------------------------------------------------------------------
# Finding 1 -- SCRAM-SHA-256 SASL handshake must not be harvested as a
# fake password. Reproduced end-to-end with a synthetic pcap so the real
# tshark dissector (not a hand-rolled stub) drives the field extraction.
# ---------------------------------------------------------------------------


def _pg_msg(msg_type: str, payload: bytes) -> bytes:
    length = 4 + len(payload)
    return msg_type.encode() + length.to_bytes(4, "big") + payload


def _startup_msg(params: dict) -> bytes:
    body = (196608).to_bytes(4, "big")  # protocol version 3.0
    for k, v in params.items():
        body += k.encode() + b"\x00" + v.encode() + b"\x00"
    body += b"\x00"
    length = 4 + len(body)
    return length.to_bytes(4, "big") + body


def _build_scram_pcap(path: str) -> None:
    """Craft a minimal, syntactically valid PostgreSQL SCRAM-SHA-256 login.

    Startup -> AuthenticationRequest(SASL) -> SASLInitialResponse ->
    AuthenticationSASLContinue -> SASLResponse -> AuthenticationSASLFinal ->
    AuthenticationOk. Raw TCP payload bytes follow the wire protocol
    (https://www.postgresql.org/docs/current/protocol-message-formats.html).
    """
    startup = _startup_msg({"user": "postgres", "database": "postgres"})

    auth_sasl = (10).to_bytes(4, "big") + b"SCRAM-SHA-256\x00" + b"\x00"
    auth_msg = _pg_msg("R", auth_sasl)

    mech = b"SCRAM-SHA-256\x00"
    client_first = b"n,,n=postgres,r=abcdefgh12345678"
    sasl_init = mech + len(client_first).to_bytes(4, "big", signed=True) + client_first
    sasl_init_msg = _pg_msg("p", sasl_init)

    server_first = b"r=abcdefgh12345678SERVERNONCE,s=U0FMVA==,i=4096"
    auth_cont_msg = _pg_msg("R", (11).to_bytes(4, "big") + server_first)

    client_final = b"c=biws,r=abcdefgh12345678SERVERNONCE,p=" + b"A" * 44
    sasl_resp_msg = _pg_msg("p", client_final)

    server_final = b"v=" + b"B" * 44
    auth_final_msg = _pg_msg("R", (12).to_bytes(4, "big") + server_final)

    auth_ok_msg = _pg_msg("R", (0).to_bytes(4, "big"))

    seq_c = 1000
    seq_s = 2000
    pkts = []

    def build(payload: bytes, from_client: bool):
        nonlocal seq_c, seq_s
        if from_client:
            pkt = (
                IP(src=CLIENT_IP, dst=SERVER_IP)
                / TCP(sport=CLIENT_PORT, dport=SERVER_PORT, flags="PA", seq=seq_c, ack=seq_s)
                / Raw(load=payload)
            )
            seq_c += len(payload)
        else:
            pkt = (
                IP(src=SERVER_IP, dst=CLIENT_IP)
                / TCP(sport=SERVER_PORT, dport=CLIENT_PORT, flags="PA", seq=seq_s, ack=seq_c)
                / Raw(load=payload)
            )
            seq_s += len(payload)
        return pkt

    syn = IP(src=CLIENT_IP, dst=SERVER_IP) / TCP(
        sport=CLIENT_PORT, dport=SERVER_PORT, flags="S", seq=seq_c
    )
    seq_c += 1
    synack = IP(src=SERVER_IP, dst=CLIENT_IP) / TCP(
        sport=SERVER_PORT, dport=CLIENT_PORT, flags="SA", seq=seq_s, ack=seq_c
    )
    seq_s += 1
    ack = IP(src=CLIENT_IP, dst=SERVER_IP) / TCP(
        sport=CLIENT_PORT, dport=SERVER_PORT, flags="A", seq=seq_c, ack=seq_s
    )

    pkts += [syn, synack, ack]
    pkts.append(build(startup, True))
    pkts.append(build(auth_msg, False))
    pkts.append(build(sasl_init_msg, True))
    pkts.append(build(auth_cont_msg, False))
    pkts.append(build(sasl_resp_msg, True))
    pkts.append(build(auth_final_msg, False))
    pkts.append(build(auth_ok_msg, False))

    wrpcap(path, pkts)


def _run_scram_pcap(tmp_path, use_ek: bool):
    import pyshark

    from oida.pcap.pgsql import PostgreSQLPassiveListener

    pcap_path = str(tmp_path / "pgsql_scram.pcap")
    _build_scram_pcap(pcap_path)

    cap_kwargs = {"input_file": pcap_path, "decode_as": {"tcp.port==5432": "pgsql"}}
    if use_ek:
        cap_kwargs["use_ek"] = True

    listener = PostgreSQLPassiveListener(interface="lo", timeout=10)
    listener._x509 = True

    cap = pyshark.FileCapture(**cap_kwargs)
    try:
        for pkt in cap:
            listener.process_packet(pkt)
    finally:
        cap.close()

    return listener


def test_finding1_scram_mechanism_name_never_harvested_ek_mode(tmp_path):
    """REFUTED: no credential secret equals the SASL mechanism name (EK mode)."""
    _skip_unless_pyshark()
    if not _ek_mode_available:
        pytest.skip("pyshark fork without use_ek support")

    listener = _run_scram_pcap(tmp_path, use_ek=True)

    bogus = [c for c in listener.credentials if c.password_or_hash == "SCRAM-SHA-256"]
    assert not bogus, f"harvested the SASL mechanism name as a fake secret: {bogus}"
    # Confirm the fixture actually exercised the SASL path (sanity check that
    # this test isn't vacuously passing because the packets never matched).
    assert any(c.auth_type == "sasl" for c in listener.credentials), (
        "sanity check failed: no SASL-auth credential/session was observed at all "
        f"-- credentials={listener.credentials}"
    )


def test_finding1_scram_mechanism_name_never_harvested_xml_mode(tmp_path):
    """REFUTED: no credential secret equals the SASL mechanism name (XML mode).

    XML mode (no use_ek) is what production actually uses for live capture
    (src/oida/pcap/pyshark_base.py builds LiveCapture without use_ek).
    """
    _skip_unless_pyshark()

    listener = _run_scram_pcap(tmp_path, use_ek=False)

    bogus = [c for c in listener.credentials if c.password_or_hash == "SCRAM-SHA-256"]
    assert not bogus, f"harvested the SASL mechanism name as a fake secret: {bogus}"
    assert any(c.auth_type == "sasl" for c in listener.credentials), (
        "sanity check failed: no SASL-auth credential/session was observed at all "
        f"-- credentials={listener.credentials}"
    )


def test_finding1_password_handler_never_invoked_for_sasl_frames(tmp_path):
    """Document *why* finding 1 does not reproduce: tshark labels SASL
    frames distinctly from "Password message", so _handle_password (the
    function the finding accuses of harvesting the mechanism name) is never
    reached for them.
    """
    _skip_unless_pyshark()
    import pyshark

    pcap_path = str(tmp_path / "pgsql_scram2.pcap")
    _build_scram_pcap(pcap_path)

    cap = pyshark.FileCapture(input_file=pcap_path, decode_as={"tcp.port==5432": "pgsql"})
    seen_types = []
    try:
        for pkt in cap:
            if hasattr(pkt, "pgsql"):
                seen_types.append(str(getattr(pkt.pgsql, "type", "")))
                assert getattr(pkt.pgsql, "password", None) is None, (
                    "pgsql.password is populated for a SASL frame -- finding 1 "
                    "reproduces on this tshark version"
                )
    finally:
        cap.close()

    assert "Password message" not in seen_types
    assert any("SASL" in t for t in seen_types), seen_types


# ---------------------------------------------------------------------------
# Finding 2 -- a post-authentication ErrorResponse must not flip an
# already-successful credential to failed.
# ---------------------------------------------------------------------------


def test_finding2_post_auth_query_error_does_not_flip_successful_credential():
    """REFUTED: cred.success stays True after an unrelated post-auth error.

    Drives the full sequence directly: PasswordMessage -> AuthenticationOk
    -> a later ErrorResponse (an ordinary SQL syntax error, not an auth
    failure). The existing ``cred.success is None`` guard in
    _handle_error_notice already protects credentials that have already
    succeeded.
    """
    listener = _make_listener()
    session = listener._get_session(CLIENT_IP, SERVER_IP, CLIENT_PORT)
    session.username = "oida"
    session.database = "postgres"

    # 1) Client sends cleartext password.
    pw_layer = _Layer(password="hunter2")
    listener._handle_password(
        NOW, CLIENT_IP, CLIENT_PORT, SERVER_IP, SERVER_PORT, "", pw_layer, flow_id="f1"
    )
    (cred_after_password,) = listener.credentials
    assert cred_after_password.success is None

    # 2) Server accepts (AuthenticationOk).
    auth_ok_layer = _Layer(authtype="0")
    listener._handle_auth_request_msg(
        NOW,
        CLIENT_IP,
        CLIENT_PORT,
        SERVER_IP,
        SERVER_PORT,
        "",
        auth_ok_layer,
        {},
        flow_id="f1",
    )
    (cred_after_auth_ok,) = listener.credentials
    assert cred_after_auth_ok.success is True

    # 3) Later, an unrelated query fails with an ordinary SQL syntax error
    #    while session.password_or_hash is still set (nothing clears it).
    assert session.password_or_hash == "hunter2"
    err_layer = _Layer(
        severity="ERROR",
        code="42601",
        message='syntax error at or near "foo"',
        file="parser.c",
        line="100",
        routine="yyerror",
    )
    listener._handle_error_notice(
        NOW, CLIENT_IP, CLIENT_PORT, SERVER_IP, SERVER_PORT, "", err_layer, "Error", flow_id="f1"
    )

    (cred_final,) = listener.credentials
    assert cred_final.success is True, (
        "an unrelated post-auth SQL error incorrectly flipped an already-successful "
        f"credential to failed: {cred_final}"
    )


def test_finding2_error_before_auth_ok_still_marks_failure():
    """Sanity check: a genuine auth failure (ERROR arrives before AuthOk,
    i.e. while success is still None) must still be recorded as failed --
    the fix direction for finding 2 must not blanket-disable failure
    tracking, only protect already-succeeded credentials.
    """
    listener = _make_listener()
    session = listener._get_session(CLIENT_IP, SERVER_IP, CLIENT_PORT)
    session.username = "oida"
    session.database = "postgres"

    pw_layer = _Layer(password="wrongpass")
    listener._handle_password(
        NOW, CLIENT_IP, CLIENT_PORT, SERVER_IP, SERVER_PORT, "", pw_layer, flow_id="f2"
    )

    err_layer = _Layer(
        severity="FATAL",
        code="28P01",
        message='password authentication failed for user "oida"',
        file="auth.c",
        line="300",
        routine="auth_failed",
    )
    listener._handle_error_notice(
        NOW, CLIENT_IP, CLIENT_PORT, SERVER_IP, SERVER_PORT, "", err_layer, "Error", flow_id="f2"
    )

    (cred,) = listener.credentials
    assert cred.success is False


# ---------------------------------------------------------------------------
# Finding 3 -- a missing pgsql.password field must not be harvested as a
# "?" secret.
# ---------------------------------------------------------------------------


def test_finding3_missing_password_field_not_recorded_as_credential():
    """CONFIRMED and FIXED: a PasswordMessage with no captured password
    field must not create a credential entry at all (previously recorded
    password_or_hash="?").
    """
    listener = _make_listener()
    session = listener._get_session(CLIENT_IP, SERVER_IP, CLIENT_PORT)
    session.username = "oida"
    session.database = "postgres"

    pw_layer = _Layer()  # no 'password' attribute -> get_field() returns None
    listener._handle_password(
        NOW, CLIENT_IP, CLIENT_PORT, SERVER_IP, SERVER_PORT, "", pw_layer, flow_id="f3"
    )

    assert listener.credentials == [], (
        f"a credential was harvested despite no password field being captured: "
        f"{listener.credentials}"
    )
    assert session.password_or_hash == "", (
        f"expected empty password_or_hash, got placeholder {session.password_or_hash!r}"
    )


def test_finding3_present_password_field_still_recorded():
    """Regression guard: the finding-3 fix must not break the normal path
    where a real password/hash IS captured.
    """
    listener = _make_listener()
    session = listener._get_session(CLIENT_IP, SERVER_IP, CLIENT_PORT)
    session.username = "oida"
    session.database = "postgres"

    pw_layer = _Layer(password="hunter2")
    listener._handle_password(
        NOW, CLIENT_IP, CLIENT_PORT, SERVER_IP, SERVER_PORT, "", pw_layer, flow_id="f4"
    )

    (cred,) = listener.credentials
    assert cred.password_or_hash == "hunter2"
    assert cred.success is None


# ---------------------------------------------------------------------------
# Finding 4 (follow-up, same placeholder bug class as finding 3): the MD5
# hashcat_format only checked ``self.salt`` for truthiness, but the handler
# stores the placeholder "?" when pgsql.salt is absent, and "?" is truthy --
# so it emitted a plausible-looking but uncrackable line "$postgres$u*?*hash".
# ---------------------------------------------------------------------------


def _md5_cred(salt):
    import datetime

    from oida.pcap.pgsql import PostgreSQLCredential

    return PostgreSQLCredential(
        username="oida",
        password_or_hash="md5" + "de" * 16,
        auth_type="md5",
        salt=salt,
        database="db",
        client_ip=CLIENT_IP,
        server_ip=SERVER_IP,
        timestamp=datetime.datetime.now(),
        success=True,
    )


@pytest.mark.parametrize("bad_salt", ["?", "", "zz", "0x1234"])
def test_finding4_placeholder_or_nonhex_salt_yields_no_hashcat_line(bad_salt):
    # FAIL-BEFORE: salt="?" produced "$postgres$oida*?*dede...".
    assert _md5_cred(bad_salt).hashcat_format == ""


@pytest.mark.parametrize("good_salt", ["ab12cd34", "AB12CD34", "ab:12:cd:34"])
def test_finding4_real_hex_salt_still_produces_hashcat_line(good_salt):
    line = _md5_cred(good_salt).hashcat_format
    assert line.startswith("$postgres$oida*")
    assert line.endswith("*" + "de" * 16)
    # salt segment is normalized to lowercase hex with separators stripped
    salt_seg = line.split("*")[1]
    assert salt_seg == "ab12cd34"
