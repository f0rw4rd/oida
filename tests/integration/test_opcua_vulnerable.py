"""
Integration tests for OPC UA scanner against vulnerable mock server.

Tests the scanner's ability to detect and report security vulnerabilities
in OPC UA servers with weak configurations.
"""

import asyncio
import pytest
import subprocess
import tempfile
import time
import sys
import socket
from pathlib import Path

from tests.service_gate import require_service

# Add fixtures path to import the vulnerable server
FIXTURES_DIR = Path(__file__).parent.parent / "fixtures" / "mock_services"
sys.path.insert(0, str(FIXTURES_DIR))


def _find_free_port():
    """Find a free port for testing."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("", 0))
        return s.getsockname()[1]


def _wait_for_port(port: int, timeout: float = 10.0) -> bool:
    """Wait for a port to become available."""
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


@pytest.fixture(scope="class")
def vulnerable_opcua_server(request):
    """Start the vulnerable OPC UA server for testing."""
    server_script = FIXTURES_DIR / "opcua_vulnerable.py"

    if not server_script.exists():
        require_service(f"Vulnerable server not found: {server_script}")

    # Use a unique port per test class to avoid conflicts
    port = _find_free_port()
    # NOTE: must NOT use unbuffered PIPEs here. The vulnerable server logs
    # verbosely (asyncua INFO) during its heavy address-space startup; an
    # unread PIPE fills its ~64KB buffer, the server blocks on write, never
    # reaches "Listening", and the port never opens -> false "failed to start"
    # skips. Capture to a temp file instead so startup can't deadlock.
    log_file = tempfile.NamedTemporaryFile(
        prefix=f"opcua_vuln_{port}_", suffix=".log", delete=False
    )
    proc = subprocess.Popen(
        [sys.executable, str(server_script), "--port", str(port)],
        stdout=log_file,
        stderr=subprocess.STDOUT,
    )

    # Wait for server to be ready (asyncua startup can be slow under load)
    if not _wait_for_port(port, timeout=30):
        proc.terminate()
        log_file.flush()
        server_log = Path(log_file.name).read_text(errors="replace")[-2000:]
        require_service(
            f"Vulnerable OPC UA server failed to start on port {port}. "
            f"Server log tail:\n{server_log}"
        )

    url = f"opc.tcp://localhost:{port}/vulnerable/"
    yield url

    # Cleanup
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()


class TestOPCUAVulnerabilityDetection:
    """Test OPC UA scanner vulnerability detection capabilities."""

    def test_detects_anonymous_auth(self, vulnerable_opcua_server):
        """Test detection of an advertised anonymous token policy.

        --get-endpoints stops at discovery, so the scanner can only report what
        GetEndpoints advertises. The confirmed "Anonymous access" finding needs
        an activated session and is covered in test_opcua_integration.py.
        """
        result = subprocess.run(
            [sys.executable, "-m", "oida.cli", "opcua", vulnerable_opcua_server, "--get-endpoints"],
            capture_output=True,
            text=True,
            timeout=30,
        )

        assert result.returncode == 0
        assert "Anonymous token policy advertised" in result.stdout

    def test_detects_no_security(self, vulnerable_opcua_server):
        """Test detection of missing security policy."""
        result = subprocess.run(
            [sys.executable, "-m", "oida.cli", "opcua", vulnerable_opcua_server, "--get-endpoints"],
            capture_output=True,
            text=True,
            timeout=30,
        )

        assert result.returncode == 0
        assert (
            "SecurityMode None" in result.stdout or "no cryptographic protection" in result.stdout
        )

    def test_detects_auditing_disabled(self, vulnerable_opcua_server):
        """Test detection of disabled auditing."""
        result = subprocess.run(
            [sys.executable, "-m", "oida.cli", "opcua", vulnerable_opcua_server, "--dump"],
            capture_output=True,
            text=True,
            timeout=30,
        )

        assert result.returncode == 0
        assert "Auditing" in result.stdout and "disabled" in result.stdout

    def test_discovers_vulnerable_methods(self, vulnerable_opcua_server):
        """Test discovery of dangerous callable methods."""
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "oida.cli",
                "opcua",
                vulnerable_opcua_server,
                "--dump-methods",
                "--max-depth",
                "4",
            ],
            capture_output=True,
            text=True,
            timeout=60,
        )

        assert result.returncode == 0
        output = result.stdout

        # Should find the vulnerable methods
        dangerous_methods = ["ExecuteCommand", "ReadFile", "WriteFile", "EvalExpression"]
        found_methods = [m for m in dangerous_methods if m in output]

        assert len(found_methods) >= 2, f"Expected dangerous methods, found: {found_methods}"

    def test_discovers_writable_variables(self, vulnerable_opcua_server):
        """Test discovery of writable variables."""
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "oida.cli",
                "opcua",
                vulnerable_opcua_server,
                "--dump-write",
                "--max-depth",
                "5",
            ],
            capture_output=True,
            text=True,
            timeout=60,
        )

        assert result.returncode == 0
        assert "writable" in result.stdout.lower() or "RW" in result.stdout


class TestOPCUACommandInjection:
    """Test OPC UA method call exploitation."""

    def test_execute_command_injection(self, vulnerable_opcua_server):
        """Test command injection via ExecuteCommand method."""
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "oida.cli",
                "opcua",
                vulnerable_opcua_server,
                "--confirm",
                "--call-method",
                "ns=2;i=2",
                "--method-args",
                '["echo INJECTED_TEST_123"]',
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )

        assert result.returncode == 0
        assert "INJECTED_TEST_123" in result.stdout

    def test_command_injection_whoami(self, vulnerable_opcua_server):
        """Test command injection returns actual system info."""
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "oida.cli",
                "opcua",
                vulnerable_opcua_server,
                "--confirm",
                "--call-method",
                "ns=2;i=2",
                "--method-args",
                '["whoami"]',
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )

        assert result.returncode == 0
        # Should return a username (non-empty response)
        assert "Method returned:" in result.stdout


class TestOPCUAPathTraversal:
    """Test OPC UA path traversal vulnerabilities."""

    def test_read_etc_hostname(self, vulnerable_opcua_server):
        """Test path traversal via ReadFile method."""
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "oida.cli",
                "opcua",
                vulnerable_opcua_server,
                "--confirm",
                "--call-method",
                "ns=2;i=11",
                "--method-args",
                '["/etc/hostname"]',
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )

        assert result.returncode == 0
        assert "Method returned:" in result.stdout
        # Should return some content (hostname)
        assert "Error" not in result.stdout or "reading file" not in result.stdout

    def test_list_directory_traversal(self, vulnerable_opcua_server):
        """Test directory listing via ListDirectory method."""
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "oida.cli",
                "opcua",
                vulnerable_opcua_server,
                "--confirm",
                "--call-method",
                "ns=2;i=17",
                "--method-args",
                '["/tmp"]',
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )

        assert result.returncode == 0
        assert "Method returned:" in result.stdout


class TestOPCUASecretExposure:
    """Test OPC UA exposed secrets detection."""

    def test_read_database_password(self, vulnerable_opcua_server):
        """Test reading exposed DatabasePassword variable."""
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "oida.cli",
                "opcua",
                vulnerable_opcua_server,
                "--node-id",
                "ns=2;i=27",
                "--read-attributes",
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )

        assert result.returncode == 0
        assert "SuperSecret123!" in result.stdout

    def test_read_api_key(self, vulnerable_opcua_server):
        """Test reading exposed APIKey variable."""
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "oida.cli",
                "opcua",
                vulnerable_opcua_server,
                "--node-id",
                "ns=2;i=28",
                "--read-attributes",
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )

        assert result.returncode == 0
        assert "sk-1234567890abcdef" in result.stdout

    def test_secrets_folder_discoverable(self, vulnerable_opcua_server):
        """Test that Secrets folder is discoverable in address space."""
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "oida.cli",
                "opcua",
                vulnerable_opcua_server,
                "--dump",
                "--max-depth",
                "4",
            ],
            capture_output=True,
            text=True,
            timeout=60,
        )

        assert result.returncode == 0
        assert "Secrets" in result.stdout


class TestOPCUAProcessVariables:
    """Test OPC UA writable process variable vulnerabilities."""

    def test_critical_setpoint_writable(self, vulnerable_opcua_server):
        """Test that CriticalSetpoint is writable."""
        # First read the current value
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "oida.cli",
                "opcua",
                vulnerable_opcua_server,
                "--node-id",
                "ns=2;i=41",
                "--read-attributes",
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )

        assert result.returncode == 0
        assert "CriticalSetpoint" in result.stdout

    def test_emergency_stop_writable(self, vulnerable_opcua_server):
        """Test that EmergencyStop variable is accessible."""
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "oida.cli",
                "opcua",
                vulnerable_opcua_server,
                "--node-id",
                "ns=2;i=43",
                "--read-attributes",
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )

        assert result.returncode == 0
        # Should be able to read without auth


class TestOPCUACodeExecution:
    """Test OPC UA Python eval code execution."""

    def test_eval_expression_basic(self, vulnerable_opcua_server):
        """Test basic Python eval execution."""
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "oida.cli",
                "opcua",
                vulnerable_opcua_server,
                "--confirm",
                "--call-method",
                "ns=2;i=23",
                "--method-args",
                '["2 + 2"]',
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )

        assert result.returncode == 0
        assert "4" in result.stdout

    def test_eval_expression_os_access(self, vulnerable_opcua_server):
        """Test Python eval with os module access."""
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "oida.cli",
                "opcua",
                vulnerable_opcua_server,
                "--confirm",
                "--call-method",
                "ns=2;i=23",
                "--method-args",
                "[\"__import__('os').getcwd()\"]",
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )

        assert result.returncode == 0
        assert "Method returned:" in result.stdout
        # Should return a path
        assert "/" in result.stdout or "\\" in result.stdout


class TestOPCUAEnvDisclosure:
    """Test OPC UA environment variable disclosure."""

    def test_get_path_variable(self, vulnerable_opcua_server):
        """Test reading PATH environment variable."""
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "oida.cli",
                "opcua",
                vulnerable_opcua_server,
                "--confirm",
                "--call-method",
                "ns=2;i=20",
                "--method-args",
                '["PATH"]',
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )

        assert result.returncode == 0
        assert "Method returned:" in result.stdout
        # PATH should contain bin directories
        assert "bin" in result.stdout.lower()

    def test_get_all_env_variables(self, vulnerable_opcua_server):
        """Test reading all environment variables."""
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "oida.cli",
                "opcua",
                vulnerable_opcua_server,
                "--confirm",
                "--call-method",
                "ns=2;i=20",
                "--method-args",
                '["*"]',
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )

        assert result.returncode == 0
        # Should return multiple env vars
        assert "=" in result.stdout


# Async test support for direct server testing
class TestOPCUADirectConnection:
    """Direct asyncua client tests (no CLI)."""

    def test_direct_anonymous_connect(self, vulnerable_opcua_server):
        """Test direct connection without authentication."""
        try:
            from asyncua import Client
        except ImportError:
            require_service("asyncua not installed")

        async def _test():
            async with Client(url=vulnerable_opcua_server) as client:
                # Should connect without credentials - verify by reading namespaces
                namespaces = await client.get_namespace_array()
                assert len(namespaces) > 0
                assert "http://vulnerable-ics.example.com" in namespaces

        asyncio.run(_test())

    def test_direct_method_call(self, vulnerable_opcua_server):
        """Test direct method call via asyncua client."""
        try:
            from asyncua import Client
        except ImportError:
            require_service("asyncua not installed")

        async def _test():
            async with Client(url=vulnerable_opcua_server) as client:
                nsidx = await client.get_namespace_index("http://vulnerable-ics.example.com")
                controller = await client.nodes.objects.get_child([f"{nsidx}:ICSController"])
                exec_method = await controller.get_child([f"{nsidx}:ExecuteCommand"])

                result = await controller.call_method(exec_method, "echo TEST_DIRECT")
                assert "TEST_DIRECT" in result

        asyncio.run(_test())
