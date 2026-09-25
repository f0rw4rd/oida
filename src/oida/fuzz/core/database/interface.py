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
    duplicate crashes together. Set by the storage layer at write time -
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
    def store_test_cases_bulk(self, test_cases: List[TestCase]) -> None:
        """Store many test cases in a single transaction.

        Hot-path optimisation: a per-row commit costs an fsync each;
        bulk-inserting the rolling buffer in one transaction collapses
        that to a single fsync.
        """

    @abstractmethod
    def store_crash(self, crash: Crash):
        """Store crash with full payload"""

    @abstractmethod
    def store_payload(
        self, test_case_id: int, request: bytes, response: Optional[bytes] = None
    ) -> None:
        """Store the request (and optional response) payload of a test case.

        Only meaningful when the backend was initialised with
        ``store_all_payloads=True``; implementations MUST silently no-op
        otherwise (crash payloads go through :meth:`store_crash`).
        """

    @abstractmethod
    def store_metadata(self, key: str, value: str):
        """Store session metadata"""

    @abstractmethod
    def store_metadata_bulk(self, items: Dict[str, str]) -> None:
        """Store many metadata key/value pairs in a single transaction."""

    @abstractmethod
    def get_test_cases(
        self,
        result_filter: Optional[str] = None,
        target_ip: Optional[str] = None,
        protocol: Optional[str] = None,
        limit: Optional[int] = 10_000,
    ) -> List[TestCase]:
        """Get test cases, optionally filtered by result/target/protocol.

        ``limit`` defaults to 10k to prevent OOM on million-case sessions.
        Pass ``None`` to return everything (replay / forensic paths).

        Ordering: rows MUST be returned newest-first (``timestamp`` descending,
        ties broken by preserving insertion order - i.e. a stable sort). All
        backends must agree on this ordering: since ``limit`` truncates the
        result set, two backends that disagree on order would return disjoint
        subsets of the data on large (>``limit``) sessions.
        """

    @abstractmethod
    def get_test_case(self, test_id: int) -> Optional[TestCase]:
        """Get specific test case by ID"""

    @abstractmethod
    def get_crash(self, test_id: int) -> Optional[Crash]:
        """Get crash information with payload"""

    @abstractmethod
    def get_all_crashes(self) -> List[Crash]:
        """Return every stored crash (for triage / reporting)."""

    @abstractmethod
    def get_payload(self, test_case_id: int) -> Optional[dict]:
        """Get the stored payload for a test case.

        Looks in the crash payloads first, then the payloads table (only
        populated in ``store_all_payloads`` mode).

        Returns:
            ``{"request": bytes | None, "response": bytes | None}`` or ``None``
            when no payload is stored for that test case.
        """

    @abstractmethod
    def get_metadata(self, key: str) -> Optional[str]:
        """Get session metadata value"""

    @abstractmethod
    def get_all_metadata(self) -> Dict[str, str]:
        """Get all session metadata"""

    @abstractmethod
    def get_stats(self) -> Dict[str, Any]:
        """Get session statistics.

        Every implementation MUST include at least this key set (callers -
        e.g. ``TestCaseManager.list_test_cases()`` - read these without a
        ``.get()`` fallback, so a missing key raises ``KeyError``):

        - ``total_test_cases``: int
        - ``passed`` / ``failed`` / ``crashed`` / ``errors``: int (by result)
        - ``pass_count`` / ``fail_count``: int (aliases of the above, kept
          for backward compatibility)
        - ``crashes_stored``: int, number of crash rows stored
        - ``db_size_bytes``: int, raw database size in bytes (0 if N/A, e.g.
          in-memory databases)
        - ``db_size_mb``: float, database size in MB (0.0 if N/A)

        Implementations may return additional backend-specific keys, but
        must never omit the ones above - see
        ``tests/unit/fuzz/test_database_backend_parity.py``.
        """
