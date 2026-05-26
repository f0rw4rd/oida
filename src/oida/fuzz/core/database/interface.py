"""
Database abstraction layer for OIDA fuzzer session storage.

This module implements lightweight session storage using deterministic replay:
- Store only test case metadata (ID, name, result, CRC32)
- Store full payloads ONLY for crashes/failures
- Use boofuzz's deterministic mutations to regenerate payloads on replay

Storage savings: ~96% reduction (1.37 GB -> 50 MB for 933K test cases)
"""

from abc import ABC, abstractmethod
from typing import List, Optional, Dict, Any
from dataclasses import dataclass


@dataclass
class TestCase:
    """Lightweight test case metadata with target tracking"""

    id: int
    name: str
    timestamp: str
    result: str  # 'pass', 'fail', 'crash', 'error'
    crc32: int  # CRC32 checksum for payload validation
    target_ip: Optional[str] = None  # Target IP address
    target_port: Optional[int] = None  # Target port
    protocol: Optional[str] = None  # Protocol name (modbus, opcua, etc.)
    duration_ms: Optional[float] = None
    monitor_status: Optional[str] = None


@dataclass
class Crash:
    """Full crash information with stored payload.

    ``crash_hash`` is a stable short signature derived from
    ``(crash_info, stack_trace top frame)`` used by triage tooling to GROUP
    duplicate crashes together. Set by the storage layer at write time —
    callers can leave it unset.
    """

    test_case_id: int
    payload: bytes
    crash_info: Optional[str] = None
    stack_trace: Optional[str] = None
    crash_hash: Optional[str] = None


@dataclass
class SessionMetadata:
    """Session metadata for deterministic replay validation"""

    protocol_name: str
    protocol_version: str  # Git commit hash
    boofuzz_version: str
    seed: Optional[int]
    config_options: str  # JSON string
    created_at: str


class DatabaseInterface(ABC):
    """Abstract interface for database operations"""

    @abstractmethod
    def init_schema(self, store_all_payloads: bool = False):
        """Initialize database schema"""

    @abstractmethod
    def store_test_case(self, test_case: TestCase) -> Optional[int]:
        """Store test case metadata and return the row id, or None"""

    @abstractmethod
    def store_crash(self, crash: Crash):
        """Store crash with full payload"""

    @abstractmethod
    def store_metadata(self, key: str, value: str):
        """Store session metadata"""

    @abstractmethod
    def get_test_cases(self, result_filter: Optional[str] = None) -> List[TestCase]:
        """Get all test cases, optionally filtered by result"""

    @abstractmethod
    def get_test_case(self, test_id: int) -> Optional[TestCase]:
        """Get specific test case by ID"""

    @abstractmethod
    def get_crash(self, test_id: int) -> Optional[Crash]:
        """Get crash information with payload"""

    @abstractmethod
    def get_metadata(self, key: str) -> Optional[str]:
        """Get session metadata value"""

    @abstractmethod
    def get_all_metadata(self) -> Dict[str, str]:
        """Get all session metadata"""

    @abstractmethod
    def get_stats(self) -> Dict[str, Any]:
        """Get session statistics"""
