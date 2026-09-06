"""Unit tests for the FTP / FTPS protocol fuzzer.

These tests exercise real behaviour without any monkey-patching of the code
under test:

- Request-definition metadata and state requirements
- Session graph construction for auth / no-auth / FTPS / data-channel modes
- Concrete rendered bytes of the boofuzz Request nodes
- FEAT capability detection driven by a real local FTP server socket
- _supports_feature gating matrix
- Connection handshake + authenticator validation via a fake socket double
- Login / auth-validation state callbacks via a fake target connection

A "fake socket" here is an input double supplied to the connection (the same
role a real TCP socket plays). It is not a patch of any method on the class
under test.
"""

import socket
import ssl
import threading

import pytest

from oida.fuzz.core.base_fuzzer import CommonState, RequestInfo
from oida.fuzz.core.config import FuzzerConfig
from oida.fuzz.core.connections.base import MockConnectionFactory
from oida.fuzz.core.stateful_fuzzer import StatefulFuzzer
from oida.fuzz.protocols.ftp import (
    FTPAuthenticator,
    FTPConnection,
    FTPFuzzer,
    FTPSConnection,
)


# ===========================================================================
# Helpers / fixtures
# ===========================================================================


class FakeSocket:
    """Scripted socket double: returns queued recv() chunks, records sends."""

    def __init__(self, recv_script=None):
        self._recv = list(recv_script or [])
        self.sent = []
        self._timeout = 5.0

    def gettimeout(self):
        return self._timeout

    def settimeout(self, value):
        self._timeout = value

    def send(self, data):
        self.sent.append(data)
        return len(data)

    def sendall(self, data):
        self.sent.append(data)

    def recv(self, _n):
        return self._recv.pop(0) if self._recv else b""

    def close(self):
        pass


def _make_config(tmp_path, name="ftp", **options):
    """Build a FuzzerConfig with a tmp session file and protocol options."""
    return FuzzerConfig(
        target_ip="127.0.0.1",
        target_port=21,
        session_filename=str(tmp_path / name),
        enumerate=options.pop("enumerate", False),
        protocol_options=options or {},
    )


def _make_fuzzer(tmp_path, name="ftp", **options):
    cfg = _make_config(tmp_path, name=name, **options)
    return FTPFuzzer(config=cfg, connection_factory=MockConnectionFactory())


def _node_names(session):
    return sorted({n.name for n in session.nodes.values() if getattr(n, "name", None)})


def _render(session, name):
    for node in session.nodes.values():
        if getattr(node, "name", None) == name:
            return node.render()
    raise KeyError(name)


# ===========================================================================
# Request definitions
# ===========================================================================


class TestRequestDefinitions:
    def test_inherits_stateful_fuzzer(self):
        assert issubclass(FTPFuzzer, StatefulFuzzer)

    def test_protocol_constants(self):
        assert FTPFuzzer.PROTOCOL_NAME == "ftp"
        assert FTPFuzzer.DEFAULT_MONITORS == "ftp:50"
        assert FTPFuzzer.CONNECTION_CLASS is FTPConnection

    def test_request_definitions_are_request_info(self):
        defs = FTPFuzzer.get_request_definitions()
        assert len(defs) == 16
        assert all(isinstance(d, RequestInfo) for d in defs)

    def test_auth_and_security_are_pre_auth(self):
        defs = {d.name: d for d in FTPFuzzer.get_request_definitions()}
        assert defs["FTP_Auth_Fuzz"].requires_state == CommonState.PRE_AUTH
        assert defs["FTP_Security"].requires_state == CommonState.PRE_AUTH
        assert defs["FTP_NoAuth_Basic"].requires_state == CommonState.PRE_AUTH

    def test_critical_path_requires_authenticated(self):
        defs = {d.name: d for d in FTPFuzzer.get_request_definitions()}
        assert defs["FTP_Critical_Path"].requires_state == CommonState.AUTHENTICATED
        assert defs["FTP_Generic"].requires_state == CommonState.ANY

    def test_protocol_options_declared(self):
        opts = FTPFuzzer.PROTOCOL_OPTIONS
        assert opts["use_tls"]["default"] is False
        assert opts["use_auth"]["default"] is True
        assert opts["datachannel_attacks"]["default"] is False
        assert opts["ftp_username"]["default"] == "anonymous"


# ===========================================================================
# Construction / options
# ===========================================================================


class TestFuzzerConstruction:
    def test_default_credentials(self, tmp_path):
        f = _make_fuzzer(tmp_path)
        assert f.username == "anonymous"
        assert f.password == "anonymous@example.com"
        assert f.use_auth is True
        assert f.use_capability_detection is True

    def test_custom_credentials_via_options(self, tmp_path):
        f = _make_fuzzer(tmp_path, ftp_username="bob", ftp_password="s3cret")
        assert f.username == "bob"
        assert f.password == "s3cret"

    def test_explicit_constructor_args_override_options(self, tmp_path):
        cfg = _make_config(tmp_path, ftp_username="ignored")
        f = FTPFuzzer(
            config=cfg,
            connection_factory=MockConnectionFactory(),
            username="explicit",
            password="pw",
            use_auth=False,
        )
        assert f.username == "explicit"
        assert f.password == "pw"
        assert f.use_auth is False

    def test_context_property_returns_state_context(self, tmp_path):
        f = _make_fuzzer(tmp_path)
        assert f.context is f._state_context

    def test_authenticator_created_when_auth_enabled(self, tmp_path):
        f = _make_fuzzer(tmp_path)
        auth = f._create_authenticator(f.config)
        assert isinstance(auth, FTPAuthenticator)
        assert auth.username == "anonymous"

    def test_authenticator_none_when_auth_disabled(self, tmp_path):
        f = _make_fuzzer(tmp_path, use_auth=False)
        assert f._create_authenticator(f.config) is None


# ===========================================================================
# Session graph construction
# ===========================================================================


class TestSessionGraph:
    def test_auth_mode_registers_core_commands(self, tmp_path):
        f = _make_fuzzer(tmp_path)
        names = _node_names(f.session)
        for cmd in ["USER", "PASS", "CWD", "MKD", "NOOP", "PWD", "SYST", "FEAT", "GENERIC"]:
            assert cmd in names, f"{cmd} missing from auth-mode session"
        # QUIT/PORT are no-auth-only commands; absent in the authenticated graph.
        assert "QUIT" not in names
        assert "PORT" not in names

    def test_auth_mode_includes_dangerous_and_security(self, tmp_path):
        f = _make_fuzzer(tmp_path)
        names = _node_names(f.session)
        for cmd in ["DELE", "RMD", "RNFR", "RNTO", "AUTH", "PBSZ", "PROT", "CCC"]:
            assert cmd in names

    def test_no_auth_mode_graph(self, tmp_path):
        f = _make_fuzzer(tmp_path, use_auth=False)
        names = _node_names(f.session)
        # No-auth basic + transfer commands present
        for cmd in ["CWD", "LIST", "PORT", "OPTS", "MKD", "SITE", "REST", "QUIT", "STOR", "RETR"]:
            assert cmd in names
        # No-auth mode does NOT register the authenticated-only baseline set
        assert "SYST" not in names
        assert "DELE" not in names

    def test_datachannel_attacks_register_dc_nodes(self, tmp_path):
        f = _make_fuzzer(tmp_path, datachannel_attacks=True)
        names = _node_names(f.session)
        for cmd in [
            "DC_Overflow_CWD",
            "DC_Overflow_STOR",
            "DC_Overflow_LIST",
            "DC_Traversal_CWD",
            "DC_Traversal_RETR",
            "DC_Format_CWD",
            "DC_Format_MKD",
        ]:
            assert cmd in names

    def test_datachannel_nodes_registered_by_default_request_enablement(self, tmp_path):
        # Data-channel requests are gated by (datachannel_attacks OR
        # is_request_enabled). With no request filter, is_request_enabled is
        # True, so the DC nodes ARE present even without the -O flag.
        f = _make_fuzzer(tmp_path)
        assert "DC_Overflow_CWD" in _node_names(f.session)

    def test_datachannel_nodes_absent_when_requests_disabled(self, tmp_path):
        # Explicitly disabling the DC requests (and leaving the -O flag off)
        # removes them from the graph.
        cfg = FuzzerConfig(
            target_ip="127.0.0.1",
            target_port=21,
            session_filename=str(tmp_path / "dc_off"),
            enumerate=False,
            disabled_requests=[
                "FTP_DC_Overflow",
                "FTP_DC_Path_Traversal",
                "FTP_DC_Format_String",
            ],
        )
        f = FTPFuzzer(config=cfg, connection_factory=MockConnectionFactory())
        names = _node_names(f.session)
        assert not any(n.startswith("DC_") for n in names)
        assert "CWD" in names  # non-DC commands still present

    def test_datachannel_flag_forces_nodes_even_if_request_disabled(self, tmp_path):
        # The -O datachannel_attacks=true flag wins over disabled_requests.
        cfg = FuzzerConfig(
            target_ip="127.0.0.1",
            target_port=21,
            session_filename=str(tmp_path / "dc_force"),
            enumerate=False,
            protocol_options={"datachannel_attacks": True},
            disabled_requests=["FTP_DC_Overflow"],
        )
        f = FTPFuzzer(config=cfg, connection_factory=MockConnectionFactory())
        assert "DC_Overflow_CWD" in _node_names(f.session)

    def test_session_is_cached(self, tmp_path):
        f = _make_fuzzer(tmp_path)
        assert f.session is f.session


# ===========================================================================
# Rendered request bytes
# ===========================================================================


class TestRenderedRequests:
    def test_cwd_default_render(self, tmp_path):
        f = _make_fuzzer(tmp_path)
        assert _render(f.session, "CWD") == b"CWD /\r\n"

    def test_simple_command_renders(self, tmp_path):
        f = _make_fuzzer(tmp_path)
        assert _render(f.session, "NOOP") == b"NOOP\r\n"
        assert _render(f.session, "PWD") == b"PWD\r\n"
        assert _render(f.session, "SYST") == b"SYST\r\n"
        assert _render(f.session, "ABOR") == b"ABOR\r\n"
        assert _render(f.session, "CDUP") == b"CDUP\r\n"

    def test_no_auth_quit_render(self, tmp_path):
        # QUIT/PORT only exist in the no-auth graph.
        f = _make_fuzzer(tmp_path, use_auth=False)
        assert _render(f.session, "QUIT") == b"QUIT\r\n"

    def test_user_pass_render_with_credentials(self, tmp_path):
        f = _make_fuzzer(tmp_path, ftp_username="alice", ftp_password="pw123")
        assert _render(f.session, "USER") == b"USER alice\r\n"
        assert _render(f.session, "PASS") == b"PASS pw123\r\n"

    def test_dc_overflow_render_is_large(self, tmp_path):
        f = _make_fuzzer(tmp_path, datachannel_attacks=True)
        rendered = _render(f.session, "DC_Overflow_CWD")
        assert rendered.startswith(b"CWD /")
        assert rendered.endswith(b"\r\n")
        assert rendered.count(b"A") >= 4096

    def test_dc_traversal_render_contains_dotdot(self, tmp_path):
        f = _make_fuzzer(tmp_path, datachannel_attacks=True)
        rendered = _render(f.session, "DC_Traversal_CWD")
        assert b"../" in rendered
        assert b"etc/passwd" in rendered

    def test_dc_format_render_contains_format_specifiers(self, tmp_path):
        f = _make_fuzzer(tmp_path, datachannel_attacks=True)
        rendered = _render(f.session, "DC_Format_MKD")
        assert rendered.startswith(b"MKD ")
        assert b"%x" in rendered

    def test_port_render(self, tmp_path):
        f = _make_fuzzer(tmp_path, use_auth=False)
        assert _render(f.session, "PORT") == b"PORT 127,0,0,1,4,0\r\n"


# ===========================================================================
# Capability detection / feature gating
# ===========================================================================


def _serve_once(srv, script):
    """Accept one connection, send each scripted chunk (reading client between)."""
    try:
        conn, _ = srv.accept()
    except OSError:
        return
    try:
        for chunk in script:
            conn.sendall(chunk)
            try:
                conn.settimeout(1.0)
                conn.recv(1024)
            except OSError:
                pass
    finally:
        conn.close()


class TestCapabilityDetection:
    def test_feat_parsing_against_local_server(self, tmp_path):
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        srv.settimeout(5.0)
        port = srv.getsockname()[1]
        script = [
            b"220 vsFTPd 3.0.3 ready.\r\n",
            b"331 need password\r\n",
            b"230 logged in\r\n",
            b"211-Features:\r\n MDTM\r\n SIZE\r\n UTF8\r\n211 End\r\n",
        ]
        t = threading.Thread(target=_serve_once, args=(srv, script), daemon=True)
        t.start()
        try:
            cfg = FuzzerConfig(
                target_ip="127.0.0.1",
                target_port=port,
                session_filename=str(tmp_path / "feat"),
                enumerate=True,
            )
            f = FTPFuzzer(config=cfg, connection_factory=MockConnectionFactory())
            assert f.server_banner == "vsFTPd 3.0.3 ready."
            assert {"MDTM", "SIZE", "UTF8"} <= f.supported_features
            # An exotic command not advertised must be reported unsupported.
            assert not f._supports_feature("HASH")
            assert f._supports_feature("SIZE")
        finally:
            srv.close()
            t.join(timeout=2)

    def test_login_failure_falls_back_to_all_features(self, tmp_path):
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        srv.settimeout(5.0)
        port = srv.getsockname()[1]
        # USER rejected -> wildcard feature set
        script = [b"220 ready\r\n", b"530 login incorrect\r\n"]
        t = threading.Thread(target=_serve_once, args=(srv, script), daemon=True)
        t.start()
        try:
            cfg = FuzzerConfig(
                target_ip="127.0.0.1",
                target_port=port,
                session_filename=str(tmp_path / "fail"),
                enumerate=True,
            )
            f = FTPFuzzer(config=cfg, connection_factory=MockConnectionFactory())
            assert f.supported_features == {"*"}
            # wildcard means everything is "supported"
            assert f._supports_feature("HASH")
        finally:
            srv.close()
            t.join(timeout=2)

    def test_narrow_feature_set_skips_unsupported_commands(self, tmp_path):
        # Server advertises only MDTM + SIZE via FEAT. With enumerate=True the
        # session graph must be built WITHOUT the unsupported exotic commands,
        # exercising the per-command _supports_feature gating and the
        # "[FEAT] Skipped N unsupported commands" summary log path.
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        srv.settimeout(5.0)
        port = srv.getsockname()[1]
        script = [
            b"220 ready\r\n",
            b"331 need pw\r\n",
            b"230 logged in\r\n",
            b"211-Features:\r\n MDTM\r\n SIZE\r\n211 End\r\n",
        ]
        t = threading.Thread(target=_serve_once, args=(srv, script), daemon=True)
        t.start()
        try:
            cfg = FuzzerConfig(
                target_ip="127.0.0.1",
                target_port=port,
                session_filename=str(tmp_path / "skip"),
                enumerate=True,
            )
            f = FTPFuzzer(config=cfg, connection_factory=MockConnectionFactory())
            assert f.supported_features == {"MDTM", "SIZE"}
            names = _node_names(f.session)
            # MDTM/SIZE supported -> present
            assert "MDTM" in names
            assert "SIZE" in names
            # Unadvertised exotic commands gated out of the session graph.
            for unsupported in ["HASH", "MLST", "MLSD", "EPSV", "EPRT", "MFMT", "MFCT", "AVBL"]:
                assert unsupported not in names, f"{unsupported} should be skipped"
            # Always-test core commands remain.
            assert "ABOR" in names
            assert "CWD" in names
        finally:
            srv.close()
            t.join(timeout=2)

    def test_connection_refused_sets_wildcard(self, tmp_path):
        # Bind+close to obtain a definitely-closed port.
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        cfg = FuzzerConfig(
            target_ip="127.0.0.1",
            target_port=port,
            session_filename=str(tmp_path / "refused"),
            enumerate=True,
        )
        f = FTPFuzzer(config=cfg, connection_factory=MockConnectionFactory())
        assert f.supported_features == {"*"}


class TestSupportsFeature:
    def test_disabled_capability_detection_supports_all(self, tmp_path):
        f = _make_fuzzer(tmp_path, use_capability_detection=False)
        f.supported_features = {"SIZE"}  # arrange: even with a narrow set
        assert f._supports_feature("HASH") is True

    def test_empty_feature_set_supports_all(self, tmp_path):
        f = _make_fuzzer(tmp_path)
        f.supported_features = set()
        assert f._supports_feature("MLST") is True

    def test_wildcard_supports_all(self, tmp_path):
        f = _make_fuzzer(tmp_path)
        f.supported_features = {"*"}
        assert f._supports_feature("ANYTHING") is True

    def test_specific_set_is_case_insensitive(self, tmp_path):
        f = _make_fuzzer(tmp_path)
        f.supported_features = {"MDTM", "SIZE"}
        assert f._supports_feature("mdtm") is True
        assert f._supports_feature("HASH") is False


class TestLogCapabilities:
    def test_early_return_when_enumerate_disabled(self, tmp_path):
        f = _make_fuzzer(tmp_path)  # enumerate defaults False
        f.server_banner = "vsFTPd"
        f.supported_features = {"SIZE"}
        # Should be a no-op and not raise even though enumerate is off.
        assert f._log_capabilities() is None


# ===========================================================================
# Connection handshake + authenticator (fake socket double)
# ===========================================================================


class TestFTPConnectionHandshake:
    def test_banner_consumed_and_stored(self):
        conn = FTPConnection("host", 21)
        conn._sock = FakeSocket([b"220 ProFTPD 1.3.5 Server ready.\r\n"])
        conn._perform_handshake()
        assert conn.server_info["banner"] == "220 ProFTPD 1.3.5 Server ready."

    def test_unexpected_banner_raises(self):
        conn = FTPConnection("host", 21)
        conn._sock = FakeSocket([b"500 not an ftp banner\r\n"])
        with pytest.raises(ConnectionError):
            conn._perform_handshake()


class TestFTPAuthenticator:
    def test_default_anonymous_credentials(self):
        auth = FTPAuthenticator()
        assert auth.username == "anonymous"
        assert auth.password == "anonymous@example.com"

    def test_validate_success_on_257(self):
        conn = FTPConnection("host", 21)
        conn._sock = FakeSocket([b'257 "/" is the current directory\r\n'])
        assert FTPAuthenticator().validate(conn) is True
        assert conn._sock.sent == [b"PWD\r\n"]

    def test_validate_failure_on_non_257(self):
        conn = FTPConnection("host", 21)
        conn._sock = FakeSocket([b"530 Please login with USER and PASS.\r\n"])
        assert FTPAuthenticator().validate(conn) is False

    def test_validate_handles_exception(self):
        conn = FTPConnection("host", 21)
        conn._sock = None  # forces an AttributeError inside _send_command
        assert FTPAuthenticator().validate(conn) is False


# ===========================================================================
# Login / auth-validation state callbacks (fake target connection)
# ===========================================================================


def _set_target_connection(fuzzer, fake):
    fuzzer.session.targets[0]._target_connection = fake


class TestLoginCallbacks:
    def test_perform_login_success(self, tmp_path):
        f = _make_fuzzer(tmp_path)
        fake = FakeSocket([b"331 need pw\r\n", b"230 logged in\r\n"])
        _set_target_connection(f, fake)
        assert f._perform_ftp_login() is True
        assert fake.sent == [b"USER anonymous\r\n", b"PASS anonymous@example.com\r\n"]

    def test_perform_login_user_rejected(self, tmp_path):
        f = _make_fuzzer(tmp_path)
        _set_target_connection(f, FakeSocket([b"530 access denied\r\n"]))
        assert f._perform_ftp_login() is False

    def test_perform_login_pass_rejected(self, tmp_path):
        f = _make_fuzzer(tmp_path)
        _set_target_connection(f, FakeSocket([b"331 need pw\r\n", b"530 bad pw\r\n"]))
        assert f._perform_ftp_login() is False

    def test_perform_login_exception_returns_false(self, tmp_path):
        f = _make_fuzzer(tmp_path)
        _set_target_connection(f, None)  # raises inside the callback
        assert f._perform_ftp_login() is False

    def test_validate_auth_success(self, tmp_path):
        f = _make_fuzzer(tmp_path)
        fake = FakeSocket([b"257 /home/user\r\n"])
        _set_target_connection(f, fake)
        assert f._validate_ftp_auth() is True
        assert fake.sent == [b"PWD\r\n"]

    def test_validate_auth_failure(self, tmp_path):
        f = _make_fuzzer(tmp_path)
        _set_target_connection(f, FakeSocket([b"530 not logged in\r\n"]))
        assert f._validate_ftp_auth() is False

    def test_validate_auth_exception(self, tmp_path):
        f = _make_fuzzer(tmp_path)
        _set_target_connection(f, None)
        assert f._validate_ftp_auth() is False


# ===========================================================================
# FTPS / TLS
# ===========================================================================


def _make_ftps_fuzzer(tmp_path, name="ftps"):
    cfg = FuzzerConfig(
        target_ip="127.0.0.1",
        target_port=21,
        session_filename=str(tmp_path / name),
        enumerate=False,
        protocol_options={"use_tls": True},
    )
    f = FTPFuzzer(config=cfg, connection_factory=MockConnectionFactory())
    _ = f.session  # trigger state-machine construction (deferred for mock conn)
    return f


class TestFTPSStateMachine:
    def test_ftps_state_machine_has_full_upgrade_chain(self, tmp_path):
        f = _make_ftps_fuzzer(tmp_path)
        states = set(f.state_machine.states.keys())
        assert {
            "CONNECTED",
            "TLS_NEGOTIATION",
            "TLS_ESTABLISHED",
            "PBSZ_SET",
            "PROT_SET",
            "AUTHENTICATED",
        } <= states

    def test_ftps_graph_still_builds_command_nodes(self, tmp_path):
        f = _make_ftps_fuzzer(tmp_path)
        names = _node_names(f.session)
        assert "CWD" in names and "USER" in names


class TestFTPSTLSCallbacks:
    def test_send_auth_tls_success(self, tmp_path):
        f = _make_ftps_fuzzer(tmp_path)
        _set_target_connection(f, FakeSocket([b"234 AUTH TLS OK\r\n"]))
        assert f._send_auth_tls() is True

    def test_send_auth_tls_rejected(self, tmp_path):
        f = _make_ftps_fuzzer(tmp_path)
        _set_target_connection(f, FakeSocket([b"500 not supported\r\n"]))
        assert f._send_auth_tls() is False

    def test_send_auth_tls_exception(self, tmp_path):
        f = _make_ftps_fuzzer(tmp_path)
        _set_target_connection(f, None)
        assert f._send_auth_tls() is False

    def test_send_pbsz_success_and_failure(self, tmp_path):
        f = _make_ftps_fuzzer(tmp_path)
        _set_target_connection(f, FakeSocket([b"200 PBSZ=0\r\n"]))
        assert f._send_pbsz() is True
        _set_target_connection(f, FakeSocket([b"503 bad sequence\r\n"]))
        assert f._send_pbsz() is False

    def test_send_pbsz_exception(self, tmp_path):
        f = _make_ftps_fuzzer(tmp_path)
        _set_target_connection(f, None)
        assert f._send_pbsz() is False

    def test_send_prot_success_and_failure(self, tmp_path):
        f = _make_ftps_fuzzer(tmp_path)
        _set_target_connection(f, FakeSocket([b"200 PROT P\r\n"]))
        assert f._send_prot() is True
        _set_target_connection(f, FakeSocket([b"534 policy denies\r\n"]))
        assert f._send_prot() is False

    def test_send_prot_exception(self, tmp_path):
        f = _make_ftps_fuzzer(tmp_path)
        _set_target_connection(f, None)
        assert f._send_prot() is False


class _ConnWithTLSVersion:
    class _Inner:
        def version(self):
            return "TLSv1.3"

    def __init__(self):
        self._sock = self._Inner()


class _ConnSecureFlag:
    is_secure = True


class _ConnNoTLSInfo:
    pass


class _ConnRaising:
    """Connection whose attribute access raises, hitting the except branch."""

    @property
    def _sock(self):
        raise RuntimeError("connection dead")


class TestFTPSValidateConnection:
    def test_validate_via_tls_version(self, tmp_path):
        f = _make_ftps_fuzzer(tmp_path)
        _set_target_connection(f, _ConnWithTLSVersion())
        assert f._validate_tls_connection() is True

    def test_validate_via_is_secure_flag(self, tmp_path):
        f = _make_ftps_fuzzer(tmp_path)
        _set_target_connection(f, _ConnSecureFlag())
        assert f._validate_tls_connection() is True

    def test_validate_unknown_assumes_valid(self, tmp_path):
        f = _make_ftps_fuzzer(tmp_path)
        _set_target_connection(f, _ConnNoTLSInfo())
        # Cannot determine state -> assumed valid (returns True with a warning)
        assert f._validate_tls_connection() is True

    def test_validate_exception_returns_false(self, tmp_path):
        f = _make_ftps_fuzzer(tmp_path)
        _set_target_connection(f, _ConnRaising())
        assert f._validate_tls_connection() is False


class _FakeTLSSock:
    def __init__(self, raise_ssl=False):
        self.raise_ssl = raise_ssl
        self.sent = []

    def send(self, data):
        if self.raise_ssl:
            raise ssl.SSLError("boom")
        self.sent.append(data)
        return len(data)

    def recv(self, _n):
        if self.raise_ssl:
            raise ssl.SSLError("boom")
        return b"RESPONSE"


class TestFTPSConnectionIO:
    def test_send_over_tls(self):
        conn = FTPSConnection("host", 990)
        conn._sock = _FakeTLSSock()
        assert conn.send(b"PWD\r\n") == 5
        assert conn._sock.sent == [b"PWD\r\n"]

    def test_send_empty_short_circuits(self):
        conn = FTPSConnection("host", 990)
        conn._sock = _FakeTLSSock()
        assert conn.send(b"") == 0

    def test_recv_over_tls(self):
        conn = FTPSConnection("host", 990)
        conn._sock = _FakeTLSSock()
        assert conn.recv(64) == b"RESPONSE"

    def test_send_ssl_error_wrapped(self):
        conn = FTPSConnection("host", 990)
        conn._sock = _FakeTLSSock(raise_ssl=True)
        with pytest.raises(Exception, match="TLS send error"):
            conn.send(b"X\r\n")

    def test_recv_ssl_error_wrapped(self):
        conn = FTPSConnection("host", 990)
        conn._sock = _FakeTLSSock(raise_ssl=True)
        with pytest.raises(Exception, match="TLS recv error"):
            conn.recv(64)

    def test_is_secure_delegates_to_handler(self):
        conn = FTPSConnection("host", 990)
        # Fresh handler has not upgraded yet.
        assert conn.is_secure is False

    def test_get_tls_info_returns_dict(self):
        conn = FTPSConnection("host", 990)
        info = conn.get_tls_info()
        assert isinstance(info, dict)
        assert "secure" in info
