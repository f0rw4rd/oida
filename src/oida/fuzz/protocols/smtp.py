"""SMTP Protocol Fuzzer

State Machine V2 Integration:
- StateContext: Carries response data between state transitions
- Response storage: Stores EHLO capabilities, STARTTLS, auth data for cross-state access
- Context-aware callbacks: State callbacks can access shared context

Integration Pattern Example:
    This fuzzer demonstrates the StateContext integration pattern:

    1. Create StateContext in __init__:
        self._state_context = StateContext()

    2. Store responses for cross-state data access:
        ctx.set_response("EHLO", ResponseData(raw=response, parsed={"capabilities": [...]}))
        ctx.set_response("AUTH", ResponseData(raw=response, parsed={"code": 235}))

    3. Access previous responses in later states:
        ehlo_resp = ctx.get_response("EHLO")
        if ehlo_resp:
            print(f"Capabilities: {ehlo_resp.parsed.get('capabilities')}")
"""

import base64
import ssl
from typing import List

from boofuzz import Block, Group, Request, Static

from ..core.base_fuzzer import BaseFuzzer, RequestInfo
from ..core.connections import TCPSocketConnection
from ..core.session import StateContext
from ..primitives.dynamic import SmartString
from ..primitives.smart_string import StringContext

import logging

logger = logging.getLogger(__name__)


class SMTPFuzzer(BaseFuzzer):
    """SMTP Protocol Fuzzer for email server security testing"""

    # Conversational protocol: the reply gates the next command.
    STATEFUL = True

    # Protocol-specific monitor: SMTP EHLO check every 50 tests
    DEFAULT_MONITORS = "smtp:50"

    PROTOCOL_OPTIONS = {
        "use_starttls": {
            "type": bool,
            "default": False,
            "description": "Use STARTTLS to upgrade to TLS",
        },
        "smtp_username": {
            "type": str,
            "default": "testuser",
            "description": "SMTP username for authentication",
            "example": "user@example.com",
        },
        "smtp_password": {
            "type": str,
            "default": "password",
            "description": "SMTP password for authentication",
            "example": "secret123",
        },
        "use_auth": {
            "type": bool,
            "default": False,
            "description": "Enable SMTP authentication and state validation",
        },
    }

    def __init__(
        self,
        config,
        username: str = None,
        password: str = None,
        use_auth: bool = None,
        connection_factory=None,
    ):
        # Authentication credentials - use options if not provided
        self.username = username or config.get_option("smtp_username", "testuser")
        self.password = password or config.get_option("smtp_password", "password")
        self.use_auth = use_auth if use_auth is not None else config.get_option("use_auth", False)

        # State Machine V2: Create shared StateContext for SMTP protocol
        # This context carries data between state transitions (EHLO -> STARTTLS -> AUTH)
        self._state_context = StateContext()

        super().__init__(config, connection_factory)

    @classmethod
    def get_request_definitions(cls) -> List[RequestInfo]:
        """Get static request definitions for --list-requests

        SMTP State Machine States:
        - CONNECTED: TCP connection established, banner received
        - EHLO_SENT: EHLO command sent, capabilities received
        - STARTTLS_SENT: STARTTLS command sent
        - TLS_ESTABLISHED: TLS handshake complete
        - EHLO_TLS_SENT: EHLO re-sent over TLS connection
        - AUTHENTICATED: AUTH successful (requires TLS or plaintext auth)
        """
        return [
            RequestInfo(
                "SMTP_Baseline",
                "Baseline connectivity test (EHLO, NOOP, QUIT)",
                "baseline",
                requires_state="CONNECTED",
            ),
            RequestInfo(
                "SMTP_Core",
                "Core SMTP commands (HELO/EHLO, MAIL FROM, RCPT TO, DATA)",
                "core",
                requires_state="EHLO_SENT",
            ),
            RequestInfo(
                "SMTP_Header_Injection",
                "CRLF header injection tests",
                "attacks",
                requires_state="EHLO_SENT",
            ),
            RequestInfo(
                "SMTP_Info",
                "Information commands (VRFY, EXPN)",
                "info",
                requires_state="EHLO_SENT",
            ),
            RequestInfo(
                "SMTP_Auth",
                "Authentication commands (AUTH LOGIN, AUTH PLAIN)",
                "auth",
                requires_state="EHLO_SENT",
            ),
            RequestInfo(
                "SMTP_STARTTLS",
                "STARTTLS upgrade testing",
                "security",
                requires_state="EHLO_SENT",
            ),
            RequestInfo(
                "SMTP_ESMTP",
                "Extended SMTP features (DSN, SIZE, BODY)",
                "esmtp",
                requires_state="EHLO_SENT",
            ),
            RequestInfo(
                "SMTP_Enhanced",
                "Enhanced DATA with MIME and DKIM",
                "enhanced",
                requires_state="AUTHENTICATED",
            ),
            RequestInfo(
                "SMTP_BDAT",
                "Binary data transfer (BDAT command)",
                "binary",
                requires_state="AUTHENTICATED",
            ),
            RequestInfo(
                "SMTP_Pipeline",
                "Pipelining test (multiple commands)",
                "pipeline",
                requires_state="AUTHENTICATED",
            ),
            RequestInfo(
                "SMTP_Overflow",
                "Oversized command/address buffer overflow",
                "overflow",
                requires_state="EHLO_SENT",
            ),
            RequestInfo(
                "SMTP_Boundary",
                "Boundary value testing (max lengths, empty fields)",
                "boundary",
                requires_state="EHLO_SENT",
            ),
        ]

    def _create_socket(self):
        return TCPSocketConnection(
            self.config.target_ip,
            self.config.target_port,
            **self._timeout_overrides(),
        )

    def setup_custom_monitors(self) -> list:
        """Setup SMTP-specific monitoring with EHLO command comparison"""
        from ..monitors import SMTPCommandMonitor

        smtp_monitor = SMTPCommandMonitor(
            host=self.config.target_ip,
            port=self.config.target_port,
            timeout=2,
            check_interval=3,  # Check every 3 test cases
        )

        return [smtp_monitor]

    def _define_protocol(self) -> None:
        """Define SMTP protocol structure for fuzzing"""

        # BASELINE: Simple connectivity test (EHLO + NOOP + QUIT)
        # This minimal test verifies SMTP service is responding before complex fuzzing
        baseline_test = Request(
            "SMTP_Baseline",
            children=(
                Block(
                    "Baseline_Commands",
                    children=(
                        Static("EHLO_Baseline", "EHLO localhost\r\n"),
                        Static("NOOP_Baseline", "NOOP\r\n"),
                        Static("QUIT_Baseline", "QUIT\r\n"),
                    ),
                ),
            ),
        )

        # 1. HELO/EHLO Command - Client identification
        helo_cmd = Request(
            "SMTP_HELO",
            children=(
                Block(
                    "HELO_Command",
                    children=(
                        Group("command", values=["HELO", "EHLO"]),
                        Static("helo_sp", " "),
                        SmartString(
                            "domain",
                            "fuzzer.example.com",
                            max_len=10000,
                            fuzzable=True,
                            context=StringContext.HOSTNAME,
                        ),
                        Static("helo_crlf", "\r\n"),
                    ),
                ),
            ),
        )

        # 2. MAIL FROM Command - Email address fuzzing
        mail_from = Request(
            "SMTP_MAIL_FROM",
            children=(
                Block(
                    "MAIL_Command",
                    children=(
                        Static("command", "MAIL FROM: "),
                        SmartString(
                            "sender_email",
                            "test@example.com",
                            max_len=4096,
                            fuzzable=True,
                            context=StringContext.CREDENTIAL,
                        ),
                        Static("mail_crlf", "\r\n"),
                    ),
                ),
            ),
        )

        # 3. RCPT TO Command - Recipient fuzzing
        rcpt_to = Request(
            "SMTP_RCPT_TO",
            children=(
                Block(
                    "RCPT_Command",
                    children=(
                        Static("command", "RCPT TO: "),
                        SmartString(
                            "recipient_email",
                            "victim@target.com",
                            max_len=100000,
                            fuzzable=True,
                            context=StringContext.CREDENTIAL,
                        ),
                        Static("rcpt_crlf", "\r\n"),
                    ),
                ),
            ),
        )

        # 4. DATA Command with strategic message fuzzing
        data_cmd = Request(
            "SMTP_DATA",
            children=(
                Block(
                    "DATA_Sequence",
                    children=(
                        Static("data_cmd", "DATA\r\n"),
                        # Message Headers - Header injection patterns
                        Block(
                            "Message_Headers",
                            children=(
                                Static("from_key", "From: "),
                                SmartString(
                                    "from_value",
                                    "sender@example.com",
                                    max_len=4096,
                                    fuzzable=True,
                                    context=StringContext.CREDENTIAL,
                                ),
                                Static("from_crlf", "\r\n"),
                                Static("to_key", "To: "),
                                SmartString(
                                    "to_value",
                                    "recipient@target.com",
                                    max_len=320,
                                    fuzzable=True,
                                    context=StringContext.CREDENTIAL,
                                ),
                                Static("to_crlf", "\r\n"),
                                Static("subject_key", "Subject: "),
                                SmartString(
                                    "subject_value",
                                    "Test Message",
                                    max_len=100000,
                                    fuzzable=True,
                                ),
                                Static("subject_crlf", "\r\n"),
                                Static("date_key", "Date: "),
                                Static("date_value", "Mon, 1 Jan 2024 12:00:00 +0000"),
                                Static("date_crlf", "\r\n"),
                                # X-Mailer header fuzzing
                                Static("mailer_key", "X-Mailer: "),
                                SmartString(
                                    "mailer_value",
                                    "OIDA",
                                    max_len=5000,
                                    fuzzable=True,
                                ),
                                Static("mailer_crlf", "\r\n"),
                            ),
                        ),
                        # Empty line separating headers from body
                        Static("headers_end", "\r\n"),
                        # Message Body - Body content attacks
                        SmartString(
                            "message_body",
                            "This is a test message.",
                            max_len=1000000,
                            fuzzable=True,
                        ),
                        Static("body_end", "\r\n.\r\n"),
                    ),
                ),
            ),
        )

        # 4.5. Header Injection Test - CRLF injection and header manipulation
        header_injection = Request(
            "SMTP_Header_Injection",
            children=(
                Block(
                    "Header_Injection_Sequence",
                    children=(
                        Static("helo", "HELO localhost\r\n"),
                        Static("mail", "MAIL FROM:<test@example.com>\r\n"),
                        Static("rcpt", "RCPT TO:<victim@target.com>\r\n"),
                        Static("data", "DATA\r\n"),
                        # Test CRLF injection in From header
                        Block(
                            "Injected_Headers",
                            children=(
                                Static("from_key", "From: "),
                                SmartString(
                                    "from_injection",
                                    "sender@example.com\r\nBcc: hidden@evil.com",
                                    max_len=512,
                                    fuzzable=True,
                                ),
                                Static("from_crlf", "\r\n"),
                                # Test CRLF injection in To header
                                Static("to_key", "To: "),
                                SmartString(
                                    "to_injection",
                                    "victim@target.com\r\nCc: attacker@evil.com",
                                    max_len=512,
                                    fuzzable=True,
                                ),
                                Static("to_crlf", "\r\n"),
                                # Test CRLF injection in Subject
                                Static("subject_key", "Subject: "),
                                SmartString(
                                    "subject_injection",
                                    "Test\r\nX-Injected-Header: malicious",
                                    max_len=512,
                                    fuzzable=True,
                                ),
                                Static("subject_crlf", "\r\n"),
                                # Additional headers for expanded testing
                                Static("reply_to_key", "Reply-To: "),
                                SmartString(
                                    "reply_to_value",
                                    "reply@example.com",
                                    max_len=320,
                                    fuzzable=True,
                                    context=StringContext.CREDENTIAL,
                                ),
                                Static("reply_to_crlf", "\r\n"),
                                Static("cc_key", "Cc: "),
                                SmartString(
                                    "cc_value",
                                    "cc@example.com",
                                    max_len=320,
                                    fuzzable=True,
                                    context=StringContext.CREDENTIAL,
                                ),
                                Static("cc_crlf", "\r\n"),
                                Static("bcc_key", "Bcc: "),
                                SmartString(
                                    "bcc_value",
                                    "bcc@example.com",
                                    max_len=320,
                                    fuzzable=True,
                                    context=StringContext.CREDENTIAL,
                                ),
                                Static("bcc_crlf", "\r\n"),
                            ),
                        ),
                        Static("headers_end", "\r\n"),
                        Static("body", "Injected message body.\r\n"),
                        Static("body_end", ".\r\n"),
                    ),
                ),
            ),
        )

        # 5. AUTH LOGIN Command - Authentication fuzzing
        auth_login = Request(
            "SMTP_AUTH_LOGIN",
            children=(
                Block(
                    "AUTH_Sequence",
                    children=(
                        Static("auth_cmd", "AUTH LOGIN\r\n"),
                        SmartString(
                            "username_b64",
                            "dGVzdA==",
                            max_len=10000,
                            fuzzable=True,
                            context=StringContext.CREDENTIAL,
                        ),
                        Static("user_crlf", "\r\n"),
                        SmartString(
                            "password_b64",
                            "cGFzc3dvcmQ=",
                            max_len=10000,
                            fuzzable=True,
                            context=StringContext.CREDENTIAL,
                        ),
                        Static("pass_crlf", "\r\n"),
                    ),
                ),
            ),
        )

        # 6. VRFY Command - User verification
        vrfy_cmd = Request(
            "SMTP_VRFY",
            children=(
                Block(
                    "VRFY_Command",
                    children=(
                        Static("vrfy", "VRFY "),
                        SmartString(
                            "username",
                            "testuser",
                            max_len=10000,
                            fuzzable=True,
                            context=StringContext.CREDENTIAL,
                        ),
                        Static("vrfy_crlf", "\r\n"),
                    ),
                ),
            ),
        )

        # 7. EXPN Command - Mailing list fuzzing
        expn_cmd = Request(
            "SMTP_EXPN",
            children=(
                Block(
                    "EXPN_Command",
                    children=(
                        Static("expn", "EXPN "),
                        SmartString(
                            "list_name",
                            "staff",
                            max_len=5000,
                            fuzzable=True,
                        ),
                        Static("expn_crlf", "\r\n"),
                    ),
                ),
            ),
        )

        # 8. ESMTP Extensions

        # AUTH PLAIN Command - Plain text authentication
        auth_plain = Request(
            "SMTP_AUTH_PLAIN",
            children=(
                Block(
                    "AUTH_PLAIN_Command",
                    children=(
                        Static("auth_cmd", "AUTH PLAIN "),
                        SmartString(
                            "auth_data",
                            "AHRlc3QAdGVzdA==",
                            max_len=10000,
                            fuzzable=True,
                            context=StringContext.CREDENTIAL,
                        ),
                        Static("auth_plain_crlf", "\r\n"),
                    ),
                ),
            ),
        )

        # STARTTLS Command - TLS upgrade
        starttls_cmd = Request(
            "SMTP_STARTTLS",
            children=(Block("STARTTLS_Command", children=(Static("starttls", "STARTTLS\r\n"),)),),
        )

        # MAIL FROM with ESMTP extensions (DSN, SIZE, etc.)
        mail_from_esmtp = Request(
            "SMTP_MAIL_FROM_ESMTP",
            children=(
                Block(
                    "MAIL_ESMTP_Command",
                    children=(
                        Static("command", "MAIL FROM:"),
                        SmartString(
                            "sender_email",
                            "<test@example.com>",
                            max_len=320,
                            fuzzable=True,
                            context=StringContext.CREDENTIAL,
                        ),
                        Static("mail_esmtp_sp", " "),
                        Group(
                            "dsn_extension",
                            values=[
                                "RET=FULL",
                                "RET=HDRS",
                                "ENVID=test123",
                                "SIZE=1000000",
                                "BODY=8BITMIME",
                                "BODY=BINARYMIME",
                                "SMTPUTF8",
                                "AUTH=<>",
                                "AUTH=test@example.com",
                            ],
                        ),
                        Static("mail_esmtp_crlf", "\r\n"),
                    ),
                ),
            ),
        )

        # RCPT TO with ESMTP extensions
        rcpt_to_esmtp = Request(
            "SMTP_RCPT_TO_ESMTP",
            children=(
                Block(
                    "RCPT_ESMTP_Command",
                    children=(
                        Static("command", "RCPT TO:"),
                        SmartString(
                            "recipient_email",
                            "<victim@target.com>",
                            max_len=320,
                            fuzzable=True,
                            context=StringContext.CREDENTIAL,
                        ),
                        Static("rcpt_esmtp_sp", " "),
                        Group(
                            "dsn_extension",
                            values=[
                                "NOTIFY=SUCCESS",
                                "NOTIFY=FAILURE",
                                "NOTIFY=DELAY",
                                "NOTIFY=SUCCESS,FAILURE,DELAY",
                                "NOTIFY=NEVER",
                                "ORCPT=rfc822;original@domain.com",
                            ],
                        ),
                        Static("rcpt_esmtp_crlf", "\r\n"),
                    ),
                ),
            ),
        )

        # BDAT Command - Binary data transfer (RFC 3030)
        bdat_cmd = Request(
            "SMTP_BDAT",
            children=(
                Block(
                    "BDAT_Command",
                    children=(
                        Static("bdat", "BDAT "),
                        SmartString(
                            "chunk_size",
                            "1024",
                            max_len=4096,
                            fuzzable=True,
                            context=StringContext.NUMERIC,
                        ),
                        Group("last_flag", values=[" LAST", ""]),
                        Static("bdat_crlf", "\r\n"),
                        SmartString(
                            "binary_data",
                            "Binary data chunk here",
                            max_len=2048,
                            fuzzable=True,
                        ),
                    ),
                ),
            ),
        )

        # Enhanced DATA with MIME and DKIM
        data_enhanced = Request(
            "SMTP_DATA_ENHANCED",
            children=(
                Block(
                    "DATA_Enhanced_Sequence",
                    children=(
                        Static("data_cmd", "DATA\r\n"),
                        # MIME Headers
                        Block(
                            "MIME_Headers",
                            children=(
                                Static("mime_version", "MIME-Version: 1.0\r\n"),
                                Static("content_type", "Content-Type: "),
                                Group(
                                    "content_type_value",
                                    values=[
                                        "text/plain; charset=utf-8",
                                        "text/html; charset=utf-8",
                                        'multipart/mixed; boundary="boundary123"',
                                        'multipart/alternative; boundary="alt123"',
                                        "application/octet-stream",
                                        "message/rfc822",
                                    ],
                                ),
                                Static("content_type_crlf", "\r\n"),
                                Static(
                                    "content_transfer_encoding",
                                    "Content-Transfer-Encoding: ",
                                ),
                                Group(
                                    "encoding_value",
                                    values=[
                                        "7bit",
                                        "8bit",
                                        "binary",
                                        "quoted-printable",
                                        "base64",
                                    ],
                                ),
                                Static("encoding_crlf", "\r\n"),
                            ),
                        ),
                        # DKIM Signature Header
                        Block(
                            "DKIM_Signature",
                            children=(
                                Static("dkim_key", "DKIM-Signature: "),
                                SmartString(
                                    "dkim_value",
                                    "v=1; a=rsa-sha256; d=example.com; s=selector1;",
                                    max_len=10000,
                                    fuzzable=True,
                                ),
                                Static("dkim_crlf", "\r\n"),
                            ),
                        ),
                        # Additional Security Headers
                        Block(
                            "Security_Headers",
                            children=(
                                Static("spf_key", "Received-SPF: "),
                                SmartString(
                                    "spf_value",
                                    "pass (google.com: domain of test@example.com)",
                                    max_len=256,
                                    fuzzable=True,
                                ),
                                Static("spf_crlf", "\r\n"),
                                Static("dmarc_key", "Authentication-Results: "),
                                SmartString(
                                    "dmarc_value",
                                    "mx.google.com; dkim=pass header.d=example.com",
                                    max_len=512,
                                    fuzzable=True,
                                ),
                                Static("dmarc_crlf", "\r\n"),
                                Static("arc_key", "ARC-Seal: "),
                                SmartString(
                                    "arc_value",
                                    "i=1; a=rsa-sha256; s=arc-20160816; d=example.com;",
                                    max_len=1024,
                                    fuzzable=True,
                                ),
                                Static("arc_crlf", "\r\n"),
                            ),
                        ),
                        # Standard headers
                        Static("from_key", "From: "),
                        SmartString(
                            "from_value",
                            "sender@example.com",
                            max_len=320,
                            fuzzable=True,
                            context=StringContext.CREDENTIAL,
                        ),
                        Static("from_crlf", "\r\n"),
                        Static("to_key", "To: "),
                        SmartString(
                            "to_value",
                            "recipient@target.com",
                            max_len=320,
                            fuzzable=True,
                            context=StringContext.CREDENTIAL,
                        ),
                        Static("to_crlf", "\r\n"),
                        Static("subject_key", "Subject: "),
                        SmartString(
                            "subject_value",
                            "Enhanced SMTP Test",
                            max_len=998,
                            fuzzable=True,
                        ),
                        Static("subject_crlf", "\r\n"),
                        # Headers end
                        Static("headers_end", "\r\n"),
                        # Message body
                        SmartString(
                            "message_body",
                            "Enhanced SMTP message with MIME and DKIM.",
                            max_len=1000000,
                            fuzzable=True,
                        ),
                        Static("body_end", "\r\n.\r\n"),
                    ),
                ),
            ),
        )

        # PIPELINING test - Multiple commands in one request
        pipelining_test = Request(
            "SMTP_PIPELINING",
            children=(
                Block(
                    "Pipeline_Commands",
                    children=(
                        Static("mail1", "MAIL FROM:<test1@example.com>\r\n"),
                        Static("rcpt1", "RCPT TO:<user1@target.com>\r\n"),
                        Static("mail2", "MAIL FROM:<test2@example.com>\r\n"),
                        Static("rcpt2", "RCPT TO:<user2@target.com>\r\n"),
                        SmartString(
                            "pipeline_data",
                            "DATA\r\nSubject: Pipeline Test\r\n\r\nPipelined message.\r\n.\r\n",
                            max_len=2048,
                            fuzzable=True,
                        ),
                    ),
                ),
            ),
        )

        # OVERFLOW: Oversized command/address buffer overflow testing
        overflow_test = Request(
            "SMTP_Overflow",
            children=(
                Block(
                    "Overflow_Commands",
                    children=(
                        Static("ehlo_cmd", "EHLO "),
                        SmartString(
                            "long_domain",
                            "A" * 4096,
                            max_len=65536,
                            fuzzable=True,
                            context=StringContext.HOSTNAME,
                        ),
                        Static("ehlo_end", "\r\n"),
                        Static("mail_cmd", "MAIL FROM:<"),
                        SmartString(
                            "long_address",
                            "x" * 2048 + "@example.com",
                            max_len=32768,
                            fuzzable=True,
                        ),
                        Static("mail_end", ">\r\n"),
                    ),
                ),
            ),
        )

        # BOUNDARY: Empty fields, max lengths, edge values
        boundary_test = Request(
            "SMTP_Boundary",
            children=(
                Block(
                    "Boundary_Commands",
                    children=(
                        # Empty EHLO domain
                        Static("ehlo_empty", "EHLO \r\n"),
                        # MAIL FROM with empty address
                        Static("mail_empty", "MAIL FROM:<>\r\n"),
                        # RCPT TO with empty address
                        Static("rcpt_empty", "RCPT TO:<>\r\n"),
                        # VRFY with empty argument
                        Static("vrfy_empty", "VRFY \r\n"),
                        # Command with max-length argument (RFC 5321: 512 octets)
                        Static("mail_max", "MAIL FROM:<"),
                        SmartString(
                            "max_local_part",
                            "a" * 64 + "@" + "b" * 255 + ".com",
                            max_len=512,
                            fuzzable=True,
                        ),
                        Static("mail_max_end", ">\r\n"),
                    ),
                ),
            ),
        )

        # ==================== TIERED REQUEST ORDERING ====================
        # Optimized ordering: baseline → simple → complex

        # TIER 1: BASELINE - Verify SMTP service responds
        if self.is_request_enabled("SMTP_Baseline"):
            self.session.connect(baseline_test)

        # TIER 2: CORE SMTP COMMANDS
        if self.is_request_enabled("SMTP_Core"):
            self.session.connect(helo_cmd)
            self.session.connect(helo_cmd, mail_from)
            self.session.connect(mail_from, rcpt_to)
            self.session.connect(rcpt_to, data_cmd)

        # Header injection tests (separate from core)
        if self.is_request_enabled("SMTP_Header_Injection"):
            self.session.connect(header_injection)

        # TIER 3: INFORMATION COMMANDS (Safe, read-only)
        if self.is_request_enabled("SMTP_Info"):
            # Ensure helo_cmd is connected first
            if not self.is_request_enabled("SMTP_Core"):
                self.session.connect(helo_cmd)
            self.session.connect(helo_cmd, vrfy_cmd)
            self.session.connect(helo_cmd, expn_cmd)

        # TIER 4: AUTHENTICATION & SECURITY
        if self.is_request_enabled("SMTP_Auth"):
            if not self.is_request_enabled("SMTP_Core") and not self.is_request_enabled(
                "SMTP_Info"
            ):
                self.session.connect(helo_cmd)
            self.session.connect(helo_cmd, auth_login)
            self.session.connect(helo_cmd, auth_plain)

        if self.is_request_enabled("SMTP_STARTTLS"):
            if (
                not self.is_request_enabled("SMTP_Core")
                and not self.is_request_enabled("SMTP_Info")
                and not self.is_request_enabled("SMTP_Auth")
            ):
                self.session.connect(helo_cmd)
            self.session.connect(helo_cmd, starttls_cmd)

        # TIER 5: ESMTP EXTENSIONS (Advanced features)
        if self.is_request_enabled("SMTP_ESMTP"):
            if (
                not self.is_request_enabled("SMTP_Core")
                and not self.is_request_enabled("SMTP_Info")
                and not self.is_request_enabled("SMTP_Auth")
                and not self.is_request_enabled("SMTP_STARTTLS")
            ):
                self.session.connect(helo_cmd)
            self.session.connect(helo_cmd, mail_from_esmtp)
            self.session.connect(mail_from_esmtp, rcpt_to_esmtp)

        if self.is_request_enabled("SMTP_Enhanced"):
            if self.is_request_enabled("SMTP_ESMTP"):
                self.session.connect(rcpt_to_esmtp, data_enhanced)

        if self.is_request_enabled("SMTP_BDAT"):
            if (
                not self.is_request_enabled("SMTP_Core")
                and not self.is_request_enabled("SMTP_Info")
                and not self.is_request_enabled("SMTP_Auth")
                and not self.is_request_enabled("SMTP_STARTTLS")
                and not self.is_request_enabled("SMTP_ESMTP")
            ):
                self.session.connect(helo_cmd)
            self.session.connect(helo_cmd, bdat_cmd)

        if self.is_request_enabled("SMTP_Pipeline"):
            if (
                not self.is_request_enabled("SMTP_Core")
                and not self.is_request_enabled("SMTP_Info")
                and not self.is_request_enabled("SMTP_Auth")
                and not self.is_request_enabled("SMTP_STARTTLS")
                and not self.is_request_enabled("SMTP_ESMTP")
                and not self.is_request_enabled("SMTP_BDAT")
            ):
                self.session.connect(helo_cmd)
            self.session.connect(helo_cmd, pipelining_test)

        # TIER 7: OVERFLOW & BOUNDARY
        if self.is_request_enabled("SMTP_Overflow"):
            self.session.connect(overflow_test)

        if self.is_request_enabled("SMTP_Boundary"):
            self.session.connect(boundary_test)

    def _define_state_machine(self) -> None:
        """
        Define SMTP state machine for STARTTLS and authentication validation

        States (standard SMTP without TLS):
        - CONNECTED: TCP connection established, banner received
        - EHLO_SENT: EHLO command sent
        - AUTHENTICATED: AUTH successful (if use_auth=True)

        States (SMTP with use_starttls=True):
        - CONNECTED: TCP connection established, banner received
        - EHLO_SENT: EHLO command sent, capabilities received
        - STARTTLS_SENT: STARTTLS command sent
        - TLS_ESTABLISHED: TLS handshake complete
        - EHLO_TLS_SENT: EHLO re-sent over TLS
        - AUTHENTICATED: AUTH successful over TLS
        """
        use_starttls = self.config.get_option("use_starttls", False)

        if not use_starttls and not self.use_auth:
            self.log.display("SMTP state machine disabled (no STARTTLS or auth)")
            return

        # State Machine V2: Log context initialization
        self.log.debug(f"[SMTP] StateContext initialized: {self._state_context}")

        if use_starttls:
            # Create SMTP STARTTLS state machine
            self._create_smtp_starttls_state_machine()
        elif self.use_auth:
            # Create simple auth state machine without TLS
            self._create_smtp_auth_state_machine()

    def _create_smtp_starttls_state_machine(self) -> None:
        """
        Create SMTP state machine with STARTTLS upgrade sequence

        This creates a detailed state machine that tracks the complete SMTP
        STARTTLS upgrade process.
        """
        from ..core.session.state_machine import (
            ProtocolState,
            StateMachine,
            StateType,
            TransitionRule,
        )

        # Define states
        connected = ProtocolState(
            name="CONNECTED",
            state_type=StateType.CONNECTION,
            description="TCP connection established, banner received",
        )

        ehlo_sent = ProtocolState(
            name="EHLO_SENT",
            state_type=StateType.SESSION,
            setup=self._send_ehlo,
            requires=["CONNECTED"],
            timeout=5.0,
            description="EHLO sent, awaiting server capabilities",
        )

        starttls_sent = ProtocolState(
            name="STARTTLS_SENT",
            state_type=StateType.SESSION,
            setup=self._send_starttls,
            requires=["EHLO_SENT"],
            timeout=5.0,
            timeout_callback=lambda: self.log.warning("STARTTLS timeout"),
            description="STARTTLS command sent, awaiting 220 response",
        )

        tls_established = ProtocolState(
            name="TLS_ESTABLISHED",
            state_type=StateType.SESSION,
            setup=self._perform_ssl_handshake,
            validation=self._validate_tls_connection,
            requires=["STARTTLS_SENT"],
            description="TLS handshake complete",
        )

        ehlo_tls_sent = ProtocolState(
            name="EHLO_TLS_SENT",
            state_type=StateType.SESSION,
            setup=self._send_ehlo,
            requires=["TLS_ESTABLISHED"],
            description="EHLO re-sent over TLS connection",
        )

        # Only add authenticated state if auth is enabled
        if self.use_auth:
            authenticated = ProtocolState(
                name="AUTHENTICATED",
                state_type=StateType.AUTHENTICATION,
                setup=self._perform_smtp_auth,
                validation=self._validate_smtp_auth,
                requires=["EHLO_TLS_SENT"],
                description="Authenticated over secure TLS channel",
            )
            states = [
                connected,
                ehlo_sent,
                starttls_sent,
                tls_established,
                ehlo_tls_sent,
                authenticated,
            ]
        else:
            states = [
                connected,
                ehlo_sent,
                starttls_sent,
                tls_established,
                ehlo_tls_sent,
            ]

        # Define transition rules
        transitions = [
            TransitionRule(
                "CONNECTED",
                "EHLO_SENT",
                description="Send EHLO to get server capabilities",
            ),
            TransitionRule(
                "EHLO_SENT",
                "STARTTLS_SENT",
                description="Initiate TLS upgrade with STARTTLS",
            ),
            TransitionRule(
                "STARTTLS_SENT", "TLS_ESTABLISHED", description="Complete TLS handshake"
            ),
            TransitionRule("TLS_ESTABLISHED", "EHLO_TLS_SENT", description="Re-send EHLO over TLS"),
        ]

        if self.use_auth:
            transitions.append(
                TransitionRule(
                    "EHLO_TLS_SENT",
                    "AUTHENTICATED",
                    description="Authenticate over TLS",
                )
            )

        # Create state machine with StateContext
        # State Machine V2: Pass context for response data propagation
        self.state_machine = StateMachine(
            initial_state=connected,
            states=states,
            transitions=transitions,
            allow_invalid_transitions=False,
            context=self._state_context,
        )

        # The STARTTLS upgrade sequence is *not* executed here.
        # _define_state_machine() runs at session-creation time, before the
        # fuzz loop opens the target connection, so driving EHLO/STARTTLS/the
        # TLS handshake now would operate on a connection that is not yet open.
        # Execution is deferred to fuzz_all() (mirroring the auth path) and the
        # setup callbacks run over a dedicated socket (_get_auth_socket).
        self.log.display(
            "SMTP STARTTLS state machine created (upgrade deferred until connection ready)"
        )

    def _run_starttls_sequence(self) -> None:
        """Drive the STARTTLS upgrade sequence over the dedicated auth socket.

        Called from fuzz_all() once the target is reachable. Like the auth
        path, the EHLO/STARTTLS/TLS handshake runs on _get_auth_socket() rather
        than boofuzz's connection (which is not open yet).
        """
        from ..core.connections.base import MockConnectionFactory

        if isinstance(self.connection_factory, MockConnectionFactory):
            self.log.display("SMTP STARTTLS upgrade skipped (mock connection)")
            return

        self.log.display("Starting SMTP STARTTLS upgrade sequence")
        try:
            self.state_machine.transition_to("EHLO_SENT")
            self.state_machine.transition_to("STARTTLS_SENT")
            self.state_machine.transition_to("TLS_ESTABLISHED")
            self.state_machine.transition_to("EHLO_TLS_SENT")

            if self.use_auth:
                self.state_machine.transition_to("AUTHENTICATED")
                self.log.display(f"SMTP authentication successful as {self.username}")
            else:
                self.log.display("SMTP STARTTLS upgrade successful")

        except Exception as e:
            self._close_auth_socket()
            self.log.fail(f"SMTP STARTTLS upgrade or authentication failed: {e}")
            raise

    def _create_smtp_auth_state_machine(self) -> None:
        """
        Create simple SMTP auth state machine without TLS

        State Machine V2: Pass context for response data propagation.
        Auth is deferred — transition happens during fuzz_all() when the
        connection is open, not during session initialization.
        """
        from ..core.session.state_machine import create_auth_state_machine

        # Create simple auth state machine with StateContext
        self.state_machine = create_auth_state_machine(
            login_callback=self._perform_smtp_auth,
            validate_callback=self._validate_smtp_auth,
            connected_validation=None,
            context=self._state_context,  # State Machine V2: Pass context
        )

        self.log.display(
            "SMTP state machine created with StateContext (auth deferred until connection ready)"
        )

    def _send_ehlo(self) -> bool:
        """
        Send EHLO command to get server capabilities

        Returns:
            True if server responds with 250
        """
        try:
            sock = self._get_auth_socket()
            ehlo_cmd = "EHLO fuzzer.example.com\r\n".encode()
            self.log.debug("Sending: EHLO fuzzer.example.com")
            sock.send(ehlo_cmd)

            # Read multi-line response
            response = sock.recv(4096).decode("utf-8", errors="ignore")
            self.log.debug(f"Response: {response.strip()}")

            # Check for 250 (Requested mail action okay, completed)
            if response.startswith("250"):
                self.log.display("EHLO accepted by server")
                return True
            else:
                self.log.fail(f"EHLO failed: {response.strip()}")
                return False

        except Exception as e:
            self.log.fail(f"Exception sending EHLO: {e}")
            return False

    def _send_starttls(self) -> bool:
        """
        Send STARTTLS command to initiate TLS upgrade

        Returns:
            True if server responds with 220 (Ready to start TLS)
        """
        try:
            sock = self._get_auth_socket()
            self.log.debug("Sending: STARTTLS")
            sock.send(b"STARTTLS\r\n")

            response = sock.recv(1024).decode("utf-8", errors="ignore")
            self.log.debug(f"Response: {response.strip()}")

            # Check for 220 (Service ready)
            if response.startswith("220"):
                self.log.display("Server ready for TLS")
                return True
            else:
                self.log.fail(f"STARTTLS failed: {response.strip()}")
                return False

        except Exception as e:
            self.log.fail(f"Exception sending STARTTLS: {e}")
            return False

    def _perform_ssl_handshake(self) -> bool:
        """
        Perform SSL/TLS handshake to upgrade connection

        Returns:
            True if SSL handshake successful
        """
        try:
            sock = self._get_auth_socket()

            # Create SSL context (verification disabled: fuzzing arbitrary targets)
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE

            # Wrap the dedicated auth socket with SSL and keep using it for the
            # remaining EHLO/AUTH exchange over TLS.
            self.log.display("Performing SSL handshake")
            self._auth_sock = ssl_context.wrap_socket(
                sock, server_side=False, server_hostname=self.config.target_ip
            )
            self._auth_sock_is_secure = True

            self.log.display("SSL handshake successful")
            return True

        except ssl.SSLError as e:
            self.log.fail(f"SSL handshake failed: {e}")
            return False
        except Exception as e:
            self.log.fail(f"Exception during SSL handshake: {e}")
            return False

    def _get_auth_socket(self):
        """Create a separate socket for SMTP authentication handshake.

        Like VNC/MMS/ADS, SMTP uses a separate socket for the pre-fuzz
        auth handshake because boofuzz's connection isn't open yet.
        """
        import socket

        if not hasattr(self, "_auth_sock") or self._auth_sock is None:
            self._auth_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._auth_sock.settimeout(10)
            self._auth_sock.connect((self.config.target_ip, self.config.target_port))
            # Read banner
            banner = self._auth_sock.recv(1024).decode("utf-8", errors="ignore")
            self.log.debug(f"SMTP banner: {banner.strip()}")
        return self._auth_sock

    def _close_auth_socket(self):
        """Close the separate auth socket."""
        if hasattr(self, "_auth_sock") and self._auth_sock:
            try:
                self._auth_sock.send(b"QUIT\r\n")
                self._auth_sock.recv(1024)
            except Exception as e:
                logger.debug(f"self._auth_sock.send(bQUITrn): {e}")
            try:
                self._auth_sock.close()
            except Exception as e:
                logger.debug(f"self._auth_sock.close(): {e}")
            self._auth_sock = None

    def _perform_smtp_auth(self) -> bool:
        """
        Execute SMTP AUTH LOGIN sequence using separate auth socket.

        Uses a dedicated socket (not boofuzz's) for the pre-fuzz handshake,
        matching the VNC/MMS/ADS pattern.

        Returns:
            True if authentication successful
        """
        try:
            sock = self._get_auth_socket()

            # Send EHLO first (required before AUTH)
            self.log.debug("Sending: EHLO fuzzer.example.com")
            sock.send(b"EHLO fuzzer.example.com\r\n")
            response = sock.recv(4096).decode("utf-8", errors="ignore")
            self.log.debug(f"EHLO response: {response.strip()}")
            if not response.startswith("250"):
                self.log.fail(f"EHLO failed: {response.strip()}")
                return False

            # Send AUTH LOGIN command
            self.log.debug("Sending: AUTH LOGIN")
            sock.send(b"AUTH LOGIN\r\n")

            # Receive 334 (server requests username)
            response = sock.recv(1024).decode("utf-8", errors="ignore")
            self.log.debug(f"Response: {response.strip()}")

            if not response.startswith("334"):
                self.log.fail(f"AUTH LOGIN failed: {response.strip()}")
                return False

            # Send base64-encoded username
            username_b64 = base64.b64encode(self.username.encode()).decode()
            self.log.debug(f"Sending username: {self.username}")
            sock.send(f"{username_b64}\r\n".encode())

            # Receive 334 (server requests password)
            response = sock.recv(1024).decode("utf-8", errors="ignore")
            self.log.debug(f"Response: {response.strip()}")

            if not response.startswith("334"):
                self.log.fail(f"Username rejected: {response.strip()}")
                return False

            # Send base64-encoded password
            password_b64 = base64.b64encode(self.password.encode()).decode()
            self.log.debug("Sending password: ****")
            sock.send(f"{password_b64}\r\n".encode())

            # Receive 235 (Authentication successful)
            response = sock.recv(1024).decode("utf-8", errors="ignore")
            self.log.debug(f"Response: {response.strip()}")

            if response.startswith("235"):
                self.log.display("SMTP authentication successful")
                return True
            else:
                self.log.fail(f"Authentication failed: {response.strip()}")
                return False

        except Exception as e:
            self.log.fail(f"Exception during SMTP authentication: {e}")
            return False

    def _validate_smtp_auth(self) -> bool:
        """
        Validate that we're still authenticated

        Uses NOOP command to check if session is still valid.

        Returns:
            True if still authenticated, False otherwise
        """
        try:
            sock = self._get_auth_socket()

            # Send NOOP command (should work if authenticated)
            self.log.debug("Validating auth with NOOP command")
            sock.send(b"NOOP\r\n")

            # Receive response
            response = sock.recv(1024).decode("utf-8", errors="ignore")
            self.log.debug(f"NOOP Response: {response.strip()}")

            # Check for 250 (OK)
            if response.startswith("250"):
                self.log.debug("Auth validation successful")
                return True
            else:
                self.log.warning(f"Auth validation failed: {response.strip()}")
                return False

        except Exception as e:
            self.log.fail(f"Exception during auth validation: {e}")
            return False

    def _validate_tls_connection(self) -> bool:
        """
        Validate that TLS connection is still active

        Returns:
            True if connection is still using TLS
        """
        try:
            sock = self._get_auth_socket()

            # The auth socket is an ssl.SSLSocket after _perform_ssl_handshake.
            if hasattr(sock, "version"):
                tls_version = sock.version()
                self.log.debug(f"TLS version: {tls_version}")
                return tls_version is not None

            # Fallback: check secure flag set during the handshake
            if getattr(self, "_auth_sock_is_secure", False):
                return True

            # Cannot determine TLS state
            self.log.warning("Cannot validate TLS connection state")
            return True  # Assume valid if cannot check

        except Exception as e:
            self.log.fail(f"Exception validating TLS: {e}")
            return False

    def fuzz_all(self) -> None:
        """Override fuzz_all to drive the SMTP pre-fuzz handshake before fuzzing.

        Both the STARTTLS upgrade and AUTH LOGIN run here (not at
        session-creation time), over a dedicated socket (like VNC/MMS/ADS),
        because boofuzz's connection is not open yet when the state machine is
        defined.
        """
        use_starttls = self.config.get_option("use_starttls", False)

        if use_starttls and self.state_machine:
            self.log.display("SMTP fuzzing with STARTTLS enabled")
            # _run_starttls_sequence drives EHLO -> STARTTLS -> TLS handshake
            # (-> EHLO over TLS -> optional AUTH) on the dedicated auth socket.
            self._run_starttls_sequence()
            self._close_auth_socket()
        elif self.use_auth and self.state_machine:
            self.log.display("SMTP fuzzing with authentication enabled")
            current_state = self.state_machine.get_current_state_name()
            if current_state != "AUTHENTICATED":
                try:
                    self.state_machine.transition_to("AUTHENTICATED")
                    self.log.display("SMTP authentication successful")
                    self._close_auth_socket()
                except Exception as e:
                    self._close_auth_socket()
                    self.log.fail(f"SMTP authentication failed: {e}")
                    raise

        super().fuzz_all()


# For backward compatibility and explicit exports
# Use SMTPFuzzer with --tls flag for SMTPS
__all__ = ["SMTPFuzzer"]
