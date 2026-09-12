"""Integration tests for OPC UA certificate-trust probes (``--test-cert-trust``).

Covers both trust layers OIDA probes:

* X509 **user-certificate** trust (OpalOPC 10016) against the mock's three
  user-cert modes, plus a positive "normal client cert auth" check:
  - ``permissive``: server trusts any user cert  -> finding must fire
  - ``reject``    : server trusts no user cert    -> clean rejection
  - ``trusted``   : server trusts one registered cert
      * our untrusted self-signed cert            -> clean rejection
      * the registered operator cert (raw client) -> session activates

* **Application/secure-channel** certificate trust (OpalOPC 10010): a server
  with secure endpoints and no client-cert trust list that lets anonymous
  sessions in accepts our untrusted app cert -> finding must fire. This guards
  the EXT_VALIDATION fix (the probe must not reject the server's own imperfect
  cert before reaching the result).

The mock is the real Docker image script (``docker/mocks/.../opcua_server.py``)
run as a subprocess, driven by the same env vars the compose variants use.
"""

import os
import socket
import subprocess
import sys
import tempfile
import time
from contextlib import contextmanager
from pathlib import Path

from tests.service_gate import require_import, require_service

REPO_ROOT = Path(__file__).resolve().parents[2]
MOCK_SCRIPT = REPO_ROOT / "docker" / "mocks" / "services" / "opcua" / "mock" / "opcua_server.py"

# The mock server needs asyncua; so do the direct-client assertions.
require_import("asyncua", reason="asyncua not installed")


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("", 0))
        return s.getsockname()[1]


def _wait_for_port(port: int, timeout: float = 30.0) -> bool:
    start = time.time()
    while time.time() - start < timeout:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                s.connect(("localhost", port))
                return True
        except (ConnectionRefusedError, socket.timeout, OSError):
            time.sleep(0.2)
    return False


@contextmanager
def _mock_server(cert_mode: str = "reject", extra_env: dict = None):
    """Start the mock OPC UA server as a subprocess.

    ``cert_mode`` sets OPCUA_USER_CERT_MODE; ``extra_env`` overrides/adds any
    other mock env vars (e.g. OPCUA_AUTH/OPCUA_SECURITY for the app-cert path).
    """
    if not MOCK_SCRIPT.exists():
        require_service(f"Mock server script not found: {MOCK_SCRIPT}")

    port = _free_port()
    cert_dir = tempfile.mkdtemp(prefix=f"opcua_{cert_mode}_certs_")
    env = {
        **os.environ,
        "OPCUA_PORT": str(port),
        "OPCUA_USER_CERT_MODE": cert_mode,
        "OPCUA_CERT_DIR": cert_dir,
        "PYTHONUNBUFFERED": "1",
        **(extra_env or {}),
    }
    # Capture logs to a file: an unread PIPE can fill and deadlock the verbose
    # asyncua startup before the listener opens (see test_opcua_vulnerable.py).
    log_file = tempfile.NamedTemporaryFile(
        prefix=f"opcua_{cert_mode}_{port}_", suffix=".log", delete=False
    )
    proc = subprocess.Popen(
        [sys.executable, str(MOCK_SCRIPT)],
        env=env,
        stdout=log_file,
        stderr=subprocess.STDOUT,
    )

    try:
        if not _wait_for_port(port, timeout=30):
            proc.terminate()
            log_file.flush()
            tail = Path(log_file.name).read_text(errors="replace")[-2000:]
            require_service(f"Mock OPC UA server ({cert_mode}) failed to start.\nLog tail:\n{tail}")

        url = f"opc.tcp://localhost:{port}/freeopcua/server/"
        yield url, cert_dir
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()


def _run_cert_trust_scan(url: str) -> str:
    """Run the scanner's --test-cert-trust probe; return stdout.

    Anonymous access is rejected on these auth-enabled servers, so the main
    auth phase fails after the pre-auth cert probe — we assert on the probe
    output (printed pre-auth) and do not require a zero return code.
    """
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "oida.cli",
            "opcua",
            url,
            "--test-cert-trust",
            "--timeout",
            "5",
        ],
        capture_output=True,
        text=True,
        timeout=90,
    )
    return result.stdout


class TestUserCertTrust:
    def test_permissive_mode_flags_self_signed_user_cert(self):
        with _mock_server("permissive") as (url, _):
            out = _run_cert_trust_scan(url)
        assert "Self-signed user certificate accepted" in out, out[-1500:]

    def test_reject_mode_reports_clean(self):
        with _mock_server("reject") as (url, _):
            out = _run_cert_trust_scan(url)
        assert "Server rejects untrusted self-signed user certificates" in out, out[-1500:]

    def test_trusted_mode_rejects_untrusted_cert(self):
        # A server that trusts a *specific* operator cert must still reject our
        # throwaway self-signed cert.
        with _mock_server("trusted") as (url, _):
            out = _run_cert_trust_scan(url)
        assert "Server rejects untrusted self-signed user certificates" in out, out[-1500:]


class TestNormalCertAuth:
    """Positive control: the registered operator cert authenticates."""

    def test_trusted_cert_authenticates(self):
        import asyncio

        from asyncua import Client

        async def _connect_with_trusted_cert(url: str, cert_dir: str) -> bool:
            client = Client(url=url, timeout=10)
            # Must match the SAN URI minted by ensure_trusted_client_cert().
            client.application_uri = "urn:oida:mock:opcua:trusted-client"
            await client.load_client_certificate(os.path.join(cert_dir, "trusted_client.der"))
            await client.load_private_key(os.path.join(cert_dir, "trusted_client_key.pem"))
            await client.connect()
            await client.disconnect()
            return True

        with _mock_server("trusted") as (url, cert_dir):
            cert = Path(cert_dir) / "trusted_client.der"
            # Server mints the trusted cert at startup; give it a moment if the
            # port opened just before the cert write completed.
            for _ in range(20):
                if cert.exists():
                    break
                time.sleep(0.2)
            assert cert.exists(), f"trusted client cert not generated in {cert_dir}"

            ok = asyncio.run(_connect_with_trusted_cert(url, cert_dir))
            assert ok


class TestAppCertTrust:
    """Application/secure-channel cert probe (OpalOPC 10010).

    Regression guard for the EXT_VALIDATION fix: before the fix the client
    rejected the server's own imperfect cert and the probe never reached a
    verdict. Now, a secure server with no client-cert trust list that admits
    anonymous sessions must be flagged as accepting our untrusted app cert.
    """

    def test_secure_anon_server_accepts_untrusted_app_cert(self):
        # OPCUA_SECURITY=true => Sign/SignAndEncrypt endpoints to probe;
        # OPCUA_AUTH=false   => anonymous sessions allowed (PermissiveUserManager);
        # mock sets no certificate_validator => any client app cert is accepted.
        with _mock_server(extra_env={"OPCUA_SECURITY": "true", "OPCUA_AUTH": "false"}) as (url, _):
            out = _run_cert_trust_scan(url)
        assert "Server ACCEPTS untrusted client certificates" in out, out[-1500:]
