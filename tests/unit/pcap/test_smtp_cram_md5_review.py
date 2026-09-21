"""Regression test: SMTP CRAM-MD5 credentials were never extracted.

Root cause (src/oida/pcap/smtp.py, "CRAM-MD5 accumulation" block, ~line 554):
the client's Base64 CRAM-MD5 response line dissects with an ``smtp`` layer
but *no* ``smtp.req.command`` / ``smtp.response.code`` field -- tshark treats
it as a bare data line. The accumulation guard ``if response_code or
command:`` therefore skips that packet entirely, it never reaches
``session.data_buffer``, and ``SMTP_CRAM_MD5_REGEX`` (which requires the full
``AUTH CRAM-MD5\\r\\n334 <challenge>\\r\\n<hash>\\r\\n235`` sequence) can never
match -- ``credentials`` and ``hashcat`` output stayed empty for every
real-world CRAM-MD5 capture.

Verified against tests/fixtures/pcap/smtp/bruteshark_smtp_cram_md5.pcap,
which is exactly this case: the client's raw base64 line is visible on the
wire as tcp.payload but carries no smtp.req.command/response.code field.
"""

import os
import shutil

import pytest

from tests.service_gate import require_service

pytestmark = [pytest.mark.unit]

_TESTS_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
FIXTURE_PATH = os.path.join(_TESTS_DIR, "fixtures", "pcap", "smtp", "bruteshark_smtp_cram_md5.pcap")

_LFS_POINTER_MAGIC = b"version https://git-lfs.github.com/spec/v1"


def _is_lfs_pointer(path) -> bool:
    try:
        with open(path, "rb") as fh:
            return fh.read(len(_LFS_POINTER_MAGIC)).startswith(_LFS_POINTER_MAGIC)
    except OSError:
        return False


_pyshark_available = False
_ek_mode_available = False
try:
    import pyshark  # noqa: F401

    _pyshark_available = bool(shutil.which("tshark"))
    if _pyshark_available:
        import inspect

        _sig = inspect.signature(pyshark.FileCapture.__init__)
        _ek_mode_available = "use_ek" in _sig.parameters
except Exception:
    pass


def _load_smtp_packets():
    """Load the CRAM-MD5 fixture the same way the production listener does."""
    if not _pyshark_available:
        require_service("pyshark/tshark not available")
    if _is_lfs_pointer(FIXTURE_PATH):
        require_service(f"pcap fixture is an unfetched git-lfs pointer: {FIXTURE_PATH}")

    import pyshark

    cap_kwargs: dict = {"input_file": FIXTURE_PATH, "display_filter": "smtp"}
    if _ek_mode_available:
        cap_kwargs["use_ek"] = True

    cap = pyshark.FileCapture(**cap_kwargs)
    packets = list(cap)
    try:
        cap.close()
    except Exception:
        pass
    return packets


class TestSMTPCramMd5CredentialExtraction:
    def test_cram_md5_credential_extracted_from_real_capture(self):
        """FAILS before the fix: credentials/hashcat stayed empty for every
        real CRAM-MD5 capture because the client's bare base64 response line
        never reached session.data_buffer."""
        from oida.pcap.smtp import SMTPPassiveListener

        listener = SMTPPassiveListener(interface="lo", timeout=1)
        packets = _load_smtp_packets()
        assert packets, "fixture produced no smtp packets -- fixture/display filter broken"

        for pkt in packets:
            listener.process_packet(pkt)

        creds = listener.get_credentials_summary()
        cram_creds = [c for c in creds if c.get("auth_method") == "CRAM-MD5"]
        assert cram_creds, (
            "No CRAM-MD5 credential extracted from bruteshark_smtp_cram_md5.pcap -- "
            "the client's bare base64 response line never reached data_buffer"
        )

        cred = cram_creds[0]
        assert cred.get("username"), "CRAM-MD5 credential has no username"
        assert cred.get("hash"), "CRAM-MD5 credential has no hash"

        hashcat_hashes = listener.get_hashcat_hashes()
        assert hashcat_hashes, "get_hashcat_hashes() returned nothing for a CRAM-MD5 credential"
        assert hashcat_hashes[0].startswith("$cram_md5$"), (
            f"unexpected hashcat format: {hashcat_hashes[0]!r}"
        )
