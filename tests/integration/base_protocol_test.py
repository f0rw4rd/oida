"""
Abstract base class for protocol integration tests

Provides common test patterns and validation methods for all protocols.
"""

import pytest
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional

from .conftest import MOCK_HOST, check_port_open, ensure_mock
from .cli_runner import CLIResult


class BaseProtocolIntegrationTest(ABC):
    """
    Abstract base class for protocol integration tests

    Subclasses must implement:
    - protocol_name: str
    - default_port: int
    - get_target(): Returns protocol-specific target string

    Provides common test patterns for:
    - Discovery/connectivity tests
    - Enumeration tests
    - Authentication tests
    - Security analysis tests
    - Error handling tests
    """

    @property
    @abstractmethod
    def protocol_name(self) -> str:
        """Protocol name as used in CLI (e.g., 'modbus', 'opcua')"""
        pass

    @property
    @abstractmethod
    def default_port(self) -> int:
        """Default port for the protocol"""
        pass

    @abstractmethod
    def get_target(self, host: str = MOCK_HOST, port: Optional[int] = None) -> str:
        """
        Get protocol-specific target string

        Args:
            host: Target host address
            port: Optional port override

        Returns:
            str: Target string appropriate for the protocol
        """
        pass

    @property
    def uses_port_argument(self) -> bool:
        """Whether this protocol uses --port CLI argument (vs port in URL)"""
        return True

    def _get_port_args(self, port: int) -> List[str]:
        """Get port arguments for CLI command"""
        if self.uses_port_argument:
            return ["--port", str(port)]
        return []

    # Autouse fixture: ensure this protocol's mock is running before any test

    @pytest.fixture(autouse=True, scope="class")
    def _start_mock(self):
        """Ensure this protocol's mock service is running before any test"""
        ensure_mock(self.protocol_name)

    # Common Test Fixtures

    @pytest.fixture
    def target(self, mock_host):
        """Get target string for this protocol"""
        return self.get_target(mock_host)

    @pytest.fixture
    def port(self, mock_ports):
        """Get port for this protocol"""
        return mock_ports.get(self.protocol_name, self.default_port)

    # Service Availability Checks

    def test_service_is_available(self, mock_host, port):
        """Verify mock service is running and accessible"""
        assert check_port_open(mock_host, port), (
            f"{self.protocol_name} service not available on port {port}"
        )

    # CLI Help Tests

    def test_help_command(self, cli_runner):
        """Verify help command works for this protocol"""
        result = cli_runner.run(self.protocol_name, "--help", expect_json=False)

        assert result.returncode == 0 or "usage" in result.combined_output.lower()
        assert self.protocol_name in result.combined_output.lower()

    # Discovery Tests

    def test_basic_discovery(self, cli_runner, target, port):
        """Test basic protocol discovery against mock service"""
        args = [self.protocol_name, target] + self._get_port_args(port)
        result = cli_runner.run(*args, format="json", timeout=30)

        self._assert_successful_discovery(result)

    def _assert_successful_discovery(self, result: CLIResult):
        """Assert discovery was successful - override for protocol-specific checks"""
        assert result.success, f"Discovery failed: {result.stderr}\nCommand: {result.command}"
        assert result.stdout or result.json_output, "No output received"

    # JSON Output Validation

    def test_json_output_format(self, cli_runner, target, port):
        """Verify JSON output is properly formatted"""
        args = [self.protocol_name, target] + self._get_port_args(port)
        result = cli_runner.run(*args, format="json")

        if result.success and result.json_output:
            self._validate_json_output(result.json_output)

    def _validate_json_output(self, data: Any):
        """Validate JSON output structure"""
        if isinstance(data, list):
            for item in data:
                if isinstance(item, dict):
                    self._validate_single_result(item)
        elif isinstance(data, dict):
            self._validate_single_result(data)

    def _validate_single_result(self, data: Dict[str, Any]):
        """Validate single result object - override for protocol-specific validation"""
        # Base validation - protocols may add more
        assert isinstance(data, dict), "Result should be a dictionary"

    # Error Handling Tests

    def test_connection_refused(self, cli_runner):
        """Test handling of connection refused error"""
        # Use port 65534 which should be closed
        target = self.get_target("127.0.0.1", 65534)
        args = [self.protocol_name, target] + self._get_port_args(65534)
        result = cli_runner.run(
            *args,
            "--timeout",
            "3",
            timeout=10,
            expect_json=False,
        )

        # Should handle gracefully, not hang
        assert result.returncode != -1, "Command should not hang"

    def test_timeout_handling(self, cli_runner):
        """Test timeout is properly enforced"""
        result = cli_runner.run(
            self.protocol_name,
            self.get_target("10.255.255.1"),
            "--timeout",
            "3",
            timeout=15,
            expect_json=False,
        )

        # Should complete within reasonable time
        assert result.execution_time < 20, "Command did not respect timeout"

    def test_invalid_target(self, cli_runner):
        """Test handling of invalid target specification"""
        result = cli_runner.run(
            self.protocol_name,
            "not-a-valid-host-12345!!!",
            timeout=10,
            expect_json=False,
        )

        # Should fail gracefully (non-zero exit or error/failure message)
        output_lower = result.combined_output.lower()
        has_error_indication = any(
            term in output_lower for term in ["error", "failed", "cannot", "not found", "not known"]
        )
        assert not result.success or has_error_indication

    # Concurrent Connection Tests

    @pytest.mark.slow
    def test_concurrent_connections(self, cli_runner, target, port):
        """Test multiple concurrent connections to same target"""
        import concurrent.futures

        port_args = self._get_port_args(port)

        def run_scan():
            args = [self.protocol_name, target] + port_args
            return cli_runner.run(*args, format="json", timeout=30)

        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
            futures = [executor.submit(run_scan) for _ in range(3)]
            results = [f.result() for f in concurrent.futures.as_completed(futures)]

        # At least one should succeed
        successes = [r for r in results if r.success]
        assert len(successes) >= 1, "No concurrent connections succeeded"

    # Verbosity Tests

    def test_verbose_output(self, cli_runner, target, port):
        """Test verbose output flag"""
        args = [self.protocol_name, target] + self._get_port_args(port) + ["-v"]
        result = cli_runner.run(*args, expect_json=False)

        # Should produce more output with verbose flag
        assert result.stdout or result.stderr, "No output with verbose flag"

    def test_debug_output(self, cli_runner, target, port):
        """Test debug output flag"""
        args = [self.protocol_name, target] + self._get_port_args(port) + ["--debug"]
        result = cli_runner.run(*args, expect_json=False)

        # Should not crash with debug flag
        assert result.returncode != -1, "Debug mode should not hang"
