"""Regression tests for SMTP fuzzer Static() literal bugs.

boofuzz's Static primitive is Static(name, default_value). Several call sites in
smtp.py passed a single positional argument (e.g. Static(" ") or Static("\\r\\n")),
which boofuzz interprets as the *name*, leaving default_value at b"" -- so the
literal separator/terminator never reaches the wire. SMTP is line-buffered, so a
command missing its trailing CRLF is never dispatched by the server and the fuzz
case tests nothing.
"""

from oida.fuzz.core.config import FuzzerConfig, ProtocolType
from oida.fuzz.core.connections import MockConnectionFactory
from oida.fuzz.protocols import PROTOCOL_FUZZERS


def _build_smtp_fuzzer():
    config = FuzzerConfig(
        target_ip="127.0.0.1",
        target_port=25,
        protocol_type=ProtocolType.TCP,
        enumerate=False,
    )
    config.log_session = False
    config.console_output = False
    config.skip_pre_send_checks = True
    config.web_interface = False
    return PROTOCOL_FUZZERS["smtp"](config=config, connection_factory=MockConnectionFactory())


def _node(fz, name):
    return next(n for n in fz.session.nodes.values() if getattr(n, "name", "") == name)


def test_smtp_helo_renders_with_space_and_crlf():
    fz = _build_smtp_fuzzer()
    data = _node(fz, "SMTP_HELO").render()
    assert data == b"HELO fuzzer.example.com\r\n"


def test_smtp_mail_from_esmtp_has_space_before_extension_and_trailing_crlf():
    fz = _build_smtp_fuzzer()
    data = _node(fz, "SMTP_MAIL_FROM_ESMTP").render()
    assert b"> RET=FULL\r\n" in data or b"> " in data
    assert data.endswith(b"\r\n")


def test_smtp_rcpt_to_esmtp_has_space_before_extension_and_trailing_crlf():
    fz = _build_smtp_fuzzer()
    data = _node(fz, "SMTP_RCPT_TO_ESMTP").render()
    assert data.endswith(b"\r\n")
    # verify separator space made it to the wire between recipient and extension
    assert b"> NOTIFY=" in data


def test_smtp_bdat_terminates_command_line_with_crlf_before_binary_data():
    fz = _build_smtp_fuzzer()
    data = _node(fz, "SMTP_BDAT").render()
    assert b"\r\n" in data
    # command line (BDAT <size>[ LAST]) must end in CRLF before the binary payload
    line, _, _rest = data.partition(b"\r\n")
    assert line.startswith(b"BDAT ")


def test_all_smtp_requests_end_with_crlf():
    # SMTP_BDAT is intentionally excluded: its command line ("BDAT <size>[ LAST]\r\n")
    # is followed by a raw binary payload block, so the *overall* render legitimately
    # does not end in CRLF -- that command line's own CRLF is checked separately in
    # test_smtp_bdat_terminates_command_line_with_crlf_before_binary_data above.
    exempt = {"SMTP_BDAT"}
    fz = _build_smtp_fuzzer()
    missing = []
    for node in fz.session.nodes.values():
        name = getattr(node, "name", "")
        if not name.startswith("SMTP_") or name in exempt:
            continue
        data = node.render()
        if not data.endswith(b"\r\n"):
            missing.append((name, data))
    assert not missing, f"SMTP requests missing trailing CRLF: {missing}"
