from abc import ABC, abstractmethod
import subprocess
from typing import List, Any
from unittest.mock import Mock


class CommandRunner(ABC):
    """Abstract interface for running system commands"""

    @abstractmethod
    def run(self, cmd: List[str], **kwargs) -> Any:
        pass


class RealCommandRunner(CommandRunner):
    """Production command runner that executes real system commands"""

    def run(self, cmd: List[str], **kwargs) -> subprocess.CompletedProcess:
        if kwargs.get("shell", False):
            raise ValueError("shell=True is not allowed for security reasons")
        return subprocess.run(cmd, **kwargs)


class MockCommandRunner(CommandRunner):
    """Mock command runner for testing"""

    def __init__(self):
        self.calls = []
        self.return_codes = [0]  # Default to success
        self.outputs = [b""]  # Default empty output
        self.errors = [b""]  # Default no errors

    def set_responses(
        self, return_codes: List[int], outputs: List[bytes] = None, errors: List[bytes] = None
    ):
        """Configure the responses for subsequent run() calls"""
        self.return_codes = return_codes.copy()
        self.outputs = outputs.copy() if outputs else [b""] * len(return_codes)
        self.errors = errors.copy() if errors else [b""] * len(return_codes)

    def run(self, cmd: List[str], **kwargs) -> Mock:
        """Mock subprocess.run behavior"""
        self.calls.append({"cmd": cmd.copy(), "kwargs": kwargs.copy()})

        result = Mock()
        result.returncode = self.return_codes.pop(0) if self.return_codes else 0
        result.stdout = self.outputs.pop(0) if self.outputs else b""
        result.stderr = self.errors.pop(0) if self.errors else b""

        return result

    def get_last_call(self):
        """Get the most recent command call for testing"""
        return self.calls[-1] if self.calls else None

    def get_all_calls(self):
        """Get all command calls for testing"""
        return self.calls.copy()
