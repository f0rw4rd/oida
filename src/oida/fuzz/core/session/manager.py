#!/usr/bin/env python3
"""
Session Manager for OIDA Fuzzer

Manages test case recording, replay, and deterministic payload regeneration.

Lightweight recording mode (default):
- Records only metadata (ID, name, result, CRC32)
- Records full payloads ONLY for crashes
- Uses boofuzz deterministic mutations for replay

Full recording mode (--store-all-payloads):
- Records all payloads for every test case
- Larger database but no regeneration needed

Rolling Buffer Mode (new default):
- Buffers test case payloads in memory using a circular buffer
- Only flushes to DB on crash/failure detection
- Stores 2 × monitor_check_interval recent test cases for crash context
- Zero DB writes for passing test cases
"""

import binascii
import json
from collections import deque
from typing import Optional, List, Tuple, TYPE_CHECKING
from datetime import datetime

from ...protocols import PROTOCOL_FUZZERS
from ..config import FuzzerConfig, hexdump
from ..database.interface import DatabaseInterface, TestCase, Crash
from ..database.orm import SQLAlchemyDatabase
from ..base_fuzzer import BaseFuzzer
from ...utils import get_git_commit_hash

if TYPE_CHECKING:
    pass


class RollingBuffer:
    """
    Fast in-memory circular buffer for test case payloads.

    Stores recent test cases in a fixed-size deque, automatically evicting
    oldest entries when full. Only flushes to database on crash detection,
    eliminating per-test-case DB writes for passing tests.

    Performance:
    - O(1) add operation (deque append)
    - O(n) flush operation (only on crash)
    - Memory: O(buffer_size × avg_payload_size)

    Example:
        buffer = RollingBuffer(maxsize=200)
        buffer.add(1, "test_name", b"payload", "2024-01-01T00:00:00")
        buffer.add(2, "test_name2", b"payload2", "2024-01-01T00:00:01")
        # On crash, flush all buffered test cases
        all_cases = buffer.get_all()
    """

    def __init__(self, maxsize: int):
        """
        Initialize rolling buffer.

        Args:
            maxsize: Maximum number of test cases to keep in buffer.
                     Older entries are automatically evicted when full.
        """
        self._buffer: deque = deque(maxlen=maxsize)
        self._total_count: int = 0
        self._maxsize = maxsize

    def add(self, test_case_id: int, name: str, payload: bytes, timestamp: str, crc32: int) -> None:
        """
        Add a test case to the buffer.

        If buffer is full, oldest entry is automatically evicted.

        Args:
            test_case_id: Unique test case identifier
            name: Test case name
            payload: Full payload bytes
            timestamp: ISO format timestamp
            crc32: CRC32 checksum of payload
        """
        self._buffer.append((test_case_id, name, payload, timestamp, crc32))
        self._total_count += 1

    def get_all(self) -> List[Tuple[int, str, bytes, str, int]]:
        """
        Get all buffered test cases.

        Returns:
            List of tuples (test_case_id, name, payload, timestamp, crc32)
        """
        return list(self._buffer)

    def clear(self) -> None:
        """Clear all buffered test cases."""
        self._buffer.clear()

    @property
    def latest_id(self) -> int:
        """Get the ID of the most recent test case, or 0 if empty."""
        return self._buffer[-1][0] if self._buffer else 0

    @property
    def total_count(self) -> int:
        """Get total number of test cases processed (including evicted)."""
        return self._total_count

    @property
    def buffer_size(self) -> int:
        """Get current number of items in buffer."""
        return len(self._buffer)

    @property
    def maxsize(self) -> int:
        """Get maximum buffer capacity."""
        return self._maxsize

    def __len__(self) -> int:
        """Return current buffer size."""
        return len(self._buffer)


class TestCaseManager:
    """
    Manages test case recording and replay with rolling buffer storage.

    Features:
    - Rolling buffer for in-memory test case storage (zero DB writes for passing tests)
    - Full crash context storage (flushes buffer on crash detection)
    - Deterministic payload regeneration
    - CRC validation for replay

    Performance:
    - Passing tests: 0 DB writes (buffer only)
    - Crashes: N INSERTs where N = buffer size (crash context)
    - Memory: O(buffer_size × avg_payload_size)
    """

    def __init__(
        self,
        fuzzer: BaseFuzzer,
        database: Optional[DatabaseInterface] = None,
        store_all_payloads: bool = False,
        read_only: bool = False,
    ):
        """
        Initialize test case manager.

        Args:
            fuzzer: Protocol fuzzer instance
            database: Optional database interface (defaults to SQLite)
            store_all_payloads: If True, store all payloads (old behavior)
            read_only: If True, the manager never writes to the session DB
                (inspection commands: list / detail / replay).
        """
        self.fuzzer = fuzzer
        self.store_all_payloads = store_all_payloads
        self.read_only = read_only
        # Use fuzzer's ICSLogger for consistent formatted output
        self._log = fuzzer.log

        if database is None:
            db_path = f"{fuzzer.config.session_filename}.db"
            self.database = SQLAlchemyDatabase(db_path)
        else:
            self.database = database

        # Initialize database schema
        self.database.init_schema(store_all_payloads=store_all_payloads)

        # Initialize rolling buffer for in-memory test case storage
        # Size: 2 × monitor_check_interval (minimum 100 for meaningful context)
        buffer_size = 2 * self.fuzzer.config.monitor_check_interval
        self._buffer = RollingBuffer(maxsize=max(buffer_size, 100))

        # Track crash count for statistics
        self._crash_count: int = 0

        # Ids already persisted to the DB by a crash-context flush. The rolling
        # buffer is intentionally NOT cleared after a flush (it keeps providing
        # crash context for later cases), so the final 'pass' flush must skip
        # these ids — re-inserting them as 'pass' would downgrade the recorded
        # crash/fail row and erase its crash-specific fields.
        self._persisted_ids: set[int] = set()

        # Edge-trigger for full-context (with-payload) crash storage: we persist a
        # CrashEvent + the buffered window's payloads once per crash *episode* (the
        # first crash-flagged case), not on every subsequent flagged case, so a
        # sustained outage doesn't create a CrashEvent per case. Reset on the next
        # passing case (episode over). Enables `oida fuzz narrow` culprit-pinning.
        self._crash_context_saved: bool = False

        # Edge-trigger for the crash EVENT itself (counter + crash-row + context
        # flush). A monitor reports a *state* (crashed=True) on every case while
        # the target stays down, so without de-bouncing a single outage during a
        # 250k-case run would report 250k crashes, write a crash row per case, and
        # grow _persisted_ids unbounded. We treat only the FIRST flagged case of an
        # episode as a distinct crash; subsequent flagged cases are folded into the
        # same episode. Reset on the next passing case (episode over).
        self._in_crash_episode: bool = False

        # Store session metadata for replay validation
        self._store_session_metadata()

        self._log.debug(
            f"Rolling buffer initialized: size={self._buffer.maxsize} "
            f"(2 × monitor_check_interval={self.fuzzer.config.monitor_check_interval})"
        )

    def _store_session_metadata(self):
        """Store session metadata for deterministic replay validation.

        Never OVERWRITES metadata already recorded for this session: the
        protocol version (git hash), seed, config options and created_at
        describe the run that produced the stored test cases. Re-writing them
        from the current process -- which every inspection command
        (list/detail/replay) used to do just by constructing a manager --
        destroys exactly the provenance a CRC-mismatch report tells the user to
        check. Only keys absent from the DB are filled in.
        """
        if self.read_only:
            return

        try:
            import boofuzz

            boofuzz_version = boofuzz.__version__
        except (ImportError, AttributeError):
            boofuzz_version = "unknown"

        metadata = {
            "protocol_name": self.fuzzer.config.protocol
            if hasattr(self.fuzzer.config, "protocol")
            else "unknown",
            "protocol_version": get_git_commit_hash(),
            "boofuzz_version": boofuzz_version,
            "seed": str(self.fuzzer.config.seed) if self.fuzzer.config.seed else "none",
            "config_options": json.dumps(self.fuzzer.config.options)
            if hasattr(self.fuzzer.config, "options")
            else "{}",
            "created_at": datetime.now().isoformat(),
            "lightweight_mode": str(not self.store_all_payloads),
        }

        existing = self.database.get_all_metadata() or {}
        new_items = {k: v for k, v in metadata.items() if k not in existing}
        if new_items:
            self.database.store_metadata_bulk(new_items)

        effective = {**metadata, **existing}
        self._log.display(
            f"Session metadata stored: {effective['protocol_name']} "
            f"v{effective['protocol_version']}"
        )

    def record_test_case(
        self,
        test_id: int,
        name: str,
        payload: bytes,
        result: str,
        target_ip: Optional[str] = None,
        target_port: Optional[int] = None,
        protocol: Optional[str] = None,
        duration_ms: Optional[float] = None,
        monitor_status: Optional[str] = None,
        crash_info: Optional[str] = None,
    ):
        """
        Record test case using rolling buffer with crash-only persistence.

        For passing tests: Only buffers in memory (zero DB writes)
        For crashes/failures: Flushes entire buffer as crash context to DB

        Args:
            test_id: Test case ID/number
            name: Test case name
            payload: Full payload bytes
            result: Result ('pass', 'fail', 'crash', 'error')
            target_ip: Target IP address
            target_port: Target port
            protocol: Protocol name (modbus, opcua, etc.)
            duration_ms: Test execution duration
            monitor_status: Monitor health check status
            crash_info: Crash information (if crashed)
        """
        if self.read_only:
            raise RuntimeError("TestCaseManager is read-only: refusing to record test cases")

        # Calculate CRC32 for validation
        crc32 = binascii.crc32(payload) & 0xFFFFFFFF
        timestamp = datetime.now().isoformat()

        # Get target info from fuzzer config if not provided
        if target_ip is None and hasattr(self.fuzzer, "config"):
            target_ip = self.fuzzer.config.target_ip
        if target_port is None and hasattr(self.fuzzer, "config"):
            target_port = self.fuzzer.config.target_port
        if protocol is None and hasattr(self.fuzzer, "config"):
            protocol = getattr(self.fuzzer.config, "protocol", None)

        # Always buffer in memory (fast, O(1) operation)
        self._buffer.add(test_id, name, payload, timestamp, crc32)

        # A passing case ends any in-flight crash episode: re-arm context capture.
        if result not in ("fail", "crash", "error"):
            self._crash_context_saved = False
            self._in_crash_episode = False

        # Periodic checkpoint: save progress every 2x monitor_check_interval
        # This protects against unexpected termination (kill -9, power loss).
        # Guard the modulus: monitor_check_interval can be 0 (or negative) from the
        # CLI, and `% 0` raises ZeroDivisionError -- which the callback's blanket
        # except would silently downgrade to a log line, persisting ZERO cases for
        # the whole run. A non-positive interval most naturally means "every case".
        flush_interval = max(1, 2 * self.fuzzer.config.monitor_check_interval)
        if self._buffer.total_count % flush_interval == 0:
            self.save_session_progress()

        # Only persist on crash/failure - flush entire buffer as crash context.
        # De-bounce the crash EVENT: a monitor's crashed *state* is reported on
        # every case while the target is down, so we act only on the episode EDGE
        # (first flagged case). Subsequent flagged cases in the same episode are
        # skipped -- no counter inflation, no per-case DB write storm, and
        # _persisted_ids stops growing once the target stays down.
        if result in ["fail", "crash", "error"]:
            if not self._in_crash_episode:
                self._in_crash_episode = True
                self._flush_crash_context(
                    crash_id=test_id,
                    crash_info=crash_info,
                    result=result,
                    target_ip=target_ip,
                    target_port=target_port,
                    protocol=protocol,
                    duration_ms=duration_ms,
                    monitor_status=monitor_status,
                )
                self._crash_count += 1
                self._log.debug(
                    f"Crash recorded: test_case={test_id}, protocol={protocol}, "
                    f"target={target_ip}:{target_port}, result={result}, "
                    f"context_size={self._buffer.buffer_size}"
                )
            else:
                self._log.debug(
                    f"Crash-state case {test_id} folded into active episode "
                    f"(no new crash record; target still down)"
                )

        # Legacy mode: store all payloads (if enabled)
        elif self.store_all_payloads:
            # Store lightweight metadata with target tracking
            test_case = TestCase(
                id=test_id,
                name=name,
                timestamp=timestamp,
                result=result,
                crc32=crc32,
                target_ip=target_ip,
                target_port=target_port,
                protocol=protocol,
                duration_ms=duration_ms,
                monitor_status=monitor_status,
            )
            self.database.store_test_case(test_case)

            # A passing test case is not a crash -- persist its payload to the
            # dedicated payloads table (what --store-all-payloads is for), not
            # the crashes table.
            self.database.store_payload(test_id, payload)

    def _flush_crash_context(
        self,
        crash_id: int,
        crash_info: Optional[str],
        result: str,
        target_ip: Optional[str],
        target_port: Optional[int],
        protocol: Optional[str],
        duration_ms: Optional[float],
        monitor_status: Optional[str],
    ) -> None:
        """
        Flush the rolling buffer to database as crash context.

        Stores all buffered test cases leading up to the crash, providing
        context for crash analysis and reproduction.

        Args:
            crash_id: Test case ID where crash was detected
            crash_info: Crash description/error message
            result: Result type ('fail', 'crash', 'error')
            target_ip: Target IP address
            target_port: Target port
            protocol: Protocol name
            duration_ms: Test execution duration
            monitor_status: Monitor health check status
        """
        buffer_contents = self._buffer.get_all()

        if not buffer_contents:
            self._log.warning(f"No buffer contents to flush for crash {crash_id}")
            return

        # Build DTO list once, then bulk-insert in a single transaction.
        # Was N per-row commits (= N fsyncs on rotating disks).
        #
        # During a crash *episode* the target stays flagged crashed, so every
        # subsequent test case lands here while the rolling buffer slides by one.
        # Re-upserting the whole overlapping window (~2 x monitor_check_interval
        # rows) on every crash-flagged case turns an O(1) record into an
        # O(buffer_size) DB write storm that also self-slows as the on-disk DB
        # grows. Skip context rows already written by an earlier flush in this
        # episode (tracked in _persisted_ids); only the not-yet-seen context rows
        # plus the crash case itself are written, so each flush is ~O(new cases).
        crash_payload = None
        cases_to_store: list[TestCase] = []
        for tc_id, tc_name, tc_payload, tc_timestamp, tc_crc32 in buffer_contents:
            is_crash_case = tc_id == crash_id
            if is_crash_case:
                crash_payload = tc_payload
            # The crash case is always (re)written so its result / crash fields
            # are set even if it was previously persisted as 'pass'; already-
            # persisted context rows are left as-is.
            if not is_crash_case and tc_id in self._persisted_ids:
                continue
            cases_to_store.append(
                TestCase(
                    id=tc_id,
                    name=tc_name,
                    timestamp=tc_timestamp,
                    result=result if is_crash_case else "pass",
                    crc32=tc_crc32,
                    target_ip=target_ip,
                    target_port=target_port,
                    protocol=protocol,
                    duration_ms=duration_ms if is_crash_case else None,
                    monitor_status=monitor_status if is_crash_case else None,
                )
            )

        if cases_to_store:
            self.database.store_test_cases_bulk(cases_to_store)

            # Remember which ids are now persisted so (a) later flushes in this
            # episode don't re-insert them and (b) the final 'pass' flush in
            # save_session_progress(final=True) does not re-insert (and downgrade)
            # them. The buffer itself is left intact for ongoing crash context.
            self._persisted_ids.update(tc.id for tc in cases_to_store)

        # Second pass: Store crash record (after test case exists)
        if crash_payload is not None:
            crash = Crash(
                test_case_id=crash_id,
                payload=crash_payload,
                crash_info=crash_info,
                stack_trace=None,
            )
            self.database.store_crash(crash)

        # Once per crash episode, persist the full buffered window WITH payloads as
        # a CrashEvent so `oida fuzz narrow` can replay it and pin the real culprit
        # (the monitor flags the crash at detection time, up to check_interval cases
        # after the case that actually broke the target). Guarded: not every DB
        # backend implements this, and it must fire only on the episode edge.
        if not self._crash_context_saved and hasattr(self.database, "store_crash_context"):
            try:
                self.database.store_crash_context(
                    detected_at_id=crash_id,
                    crash_info=crash_info,
                    target_ip=target_ip,
                    target_port=target_port,
                    protocol=protocol,
                    buffer_contents=buffer_contents,
                )
                self._crash_context_saved = True
            except Exception as e:
                self._log.debug(f"Could not store crash context for {crash_id}: {e}")

        self._log.debug(
            f"Flushed {len(cases_to_store)} new test cases "
            f"(of {len(buffer_contents)} buffered) as crash context for crash {crash_id}"
        )

    def get_progress(self) -> dict:
        """
        Get progress information from the rolling buffer.

        Returns:
            Dictionary with current_case, total_processed, crash_count, buffer_size
        """
        return {
            "current_case": self._buffer.latest_id,
            "total_processed": self._buffer.total_count,
            "actual_sends": getattr(self, "_actual_sends", 0),
            "crash_count": self._crash_count,
            "buffer_size": self._buffer.buffer_size,
            "buffer_maxsize": self._buffer.maxsize,
        }

    def save_session_progress(self, final: bool = False) -> None:
        """
        Save session progress to database metadata.

        Call this when fuzzing ends (normally or via interrupt) to persist
        the last test case number for resume functionality.

        Args:
            final: If True, print summary to stdout (for Ctrl+C / end of session)
        """
        if self.read_only:
            self._log.debug("Read-only manager: skipping session progress save")
            return

        try:
            progress = self.get_progress()

            # boofuzz's own counters. total_mutant_index is the mutation-space POSITION;
            # it decomposes as resume_base + sent + skipped:
            #   resume_base = mutations covered by EARLIER sessions, fast-forwarded on resume
            #                 (index_start-1) — already fuzzed, not skipped now.
            #   sent        = num_cases_actually_fuzzed — transmitted THIS run.
            #   skipped     = within-run jumps (boofuzz crash-threshold fast-forward).
            # None of these is a recording loss.
            bf_session = getattr(self.fuzzer, "session", None)
            total_mutant_index = getattr(bf_session, "total_mutant_index", None)
            num_actually_fuzzed = getattr(bf_session, "num_cases_actually_fuzzed", None)

            cfg = getattr(self.fuzzer, "config", None)
            index_start = getattr(cfg, "index_start", 1) or 1
            resume_base = max(0, index_start - 1)

            # `total` (boofuzz position) — fall back to the last sent index if the session
            # object is gone, so it never reads below the sent count.
            total = (
                total_mutant_index if total_mutant_index is not None else progress["current_case"]
            )
            sent = progress["total_processed"]
            skipped = max(0, total - sent - resume_base)

            metadata = {
                "last_test_case": str(progress["current_case"]),
                "total_processed": str(progress["total_processed"]),
                "actual_sends": str(progress["actual_sends"]),
                "crash_count": str(progress["crash_count"]),
                "final_mutant_index": str(total),
                "resume_base": str(resume_base),
                "last_updated": datetime.now().isoformat(),
            }
            # One transaction instead of five — saves four fsyncs per save.
            self.database.store_metadata_bulk(metadata)

            # Verification: boofuzz's executed-case counter should match what we recorded.
            # If these ever diverge, recording IS dropping cases (a real bug) rather than
            # boofuzz merely skipping/resuming.
            if num_actually_fuzzed is not None:
                self._log.debug(
                    f"counter check: boofuzz_fuzzed={num_actually_fuzzed} "
                    f"recorded={sent} total_mutant_index={total_mutant_index} "
                    f"resume_base={resume_base} skipped={skipped}"
                )

            # At session end, flush the buffered (non-crash) test-case metadata to
            # the DB in one bulk transaction. Per-case writes stay zero-cost during
            # fuzzing (crash-only persistence); this just makes a completed session
            # DB reflect the cases that ran, without storing full payloads.
            if final and not self.store_all_payloads:
                buffered = self._buffer.get_all()
                if buffered:
                    cfg = getattr(self.fuzzer, "config", None)
                    target_ip = getattr(cfg, "target_ip", None)
                    target_port = getattr(cfg, "target_port", None)
                    protocol = getattr(cfg, "protocol", None)
                    # Skip ids already persisted as crash context — re-inserting
                    # them as 'pass' would clobber the recorded crash/fail row.
                    pending = [
                        TestCase(
                            id=tc_id,
                            name=name,
                            timestamp=ts,
                            result="pass",
                            crc32=crc,
                            target_ip=target_ip,
                            target_port=target_port,
                            protocol=protocol,
                        )
                        for (tc_id, name, _payload, ts, crc) in buffered
                        if tc_id not in self._persisted_ids
                    ]
                    if pending:
                        self.database.store_test_cases_bulk(pending)
            # Only print on final save (Ctrl+C or end of session)
            if final:
                line = (
                    f"Session saved: sent={sent:,}, skipped={skipped:,}, "
                    f"total={total:,}, crashes={progress['crash_count']:,}"
                )
                if resume_base:
                    line += f" (resumed past {resume_base:,} earlier cases)"
                self._log.display(line)
            self._log.debug("Session progress saved to database")
        except Exception as e:
            self._log.fail(f"Failed to save session progress: {e}")

    def register_callbacks(self):
        """
        Register callbacks with the fuzzer's session to automatically record test cases.

        This hooks into boofuzz's post_test_case callback to capture and record each test case.
        """
        # Track actual sends (callback invocations with non-empty payload)
        self._actual_sends = 0

        def record_callback(target, fuzz_data_logger, session, *args, **kwargs):
            """Callback to record each test case"""
            try:
                # Get test case information from session
                test_case_id = session.total_mutant_index
                test_case_name = session.fuzz_node.name if session.fuzz_node else "unknown"

                # Get payload that was sent from session.last_send
                payload = (
                    session.last_send
                    if hasattr(session, "last_send") and session.last_send
                    else b""
                )

                # Track actual sends (when callback is invoked with a payload)
                # This counts every test case where data was actually sent
                if payload:
                    self._actual_sends += 1

                # Convert to bytes if needed
                if not isinstance(payload, bytes):
                    try:
                        payload = bytes(payload)
                    except (TypeError, ValueError) as e:
                        self._log.debug(f"Failed to convert payload to bytes: {e}")
                        payload = b""

                # Check if monitors detected a failure
                result = "pass"
                crash_info = None

                # Check boofuzz's fuzz_data_logger for failures logged during this test case
                # This is the primary source of truth for crash detection
                if hasattr(session, "_fuzz_data_logger") and session._fuzz_data_logger:
                    fdl = session._fuzz_data_logger
                    if hasattr(fdl, "failed_test_cases") and fdl.failed_test_cases:
                        # Check if current test case has logged failures
                        current_test_id = getattr(fdl, "most_recent_test_id", None)
                        if current_test_id and current_test_id in fdl.failed_test_cases:
                            failures = fdl.failed_test_cases[current_test_id]
                            if failures:
                                result = "crash"
                                crash_info = f"Boofuzz detected failure: {failures[0][:200] if failures else 'unknown'}"

                # Check session's crash detection flags (set from previous failures)
                if result == "pass" and hasattr(session, "is_paused") and session.is_paused:
                    result = "crash"
                    crash_info = "Session paused due to crash threshold"

                # Check for crashing primitives (set from previous failures)
                if (
                    result == "pass"
                    and hasattr(session, "crashing_primitives")
                    and session.crashing_primitives
                ):
                    if test_case_name in session.crashing_primitives:
                        result = "crash"
                        crash_info = f"Crashing primitive: {test_case_name}"

                # Check monitor_results for this test case (set after _process_failures)
                if (
                    result == "pass"
                    and hasattr(session, "monitor_results")
                    and session.monitor_results
                ):
                    if test_case_id in session.monitor_results:
                        result = "crash"
                        crash_info = f"Monitor result: {session.monitor_results[test_case_id][0][:200] if session.monitor_results[test_case_id] else 'unknown'}"

                # Check target monitor results (including nested monitors in CombinedMonitor)
                if result == "pass" and hasattr(target, "monitors") and target.monitors:
                    for monitor in target.monitors:
                        # Check for crashed state (ProtocolMonitor pattern)
                        if getattr(monitor, "crashed", False):
                            result = "crash"
                            monitor_crash_info = getattr(monitor, "crash_info", None)
                            if monitor_crash_info:
                                crash_info = f"Monitor crash: {monitor_crash_info.get('target', 'unknown')} at {monitor_crash_info.get('timestamp', 'unknown')}"
                            else:
                                crash_info = f"Monitor detected crash (consecutive_failures={getattr(monitor, 'consecutive_failures', 0)})"
                            break
                        # Fallback: check consecutive_failures directly (for legacy monitors)
                        if (
                            hasattr(monitor, "consecutive_failures")
                            and monitor.consecutive_failures > 0
                        ):
                            result = "crash"
                            crash_info = f"Monitor detected {monitor.consecutive_failures} consecutive failures"
                            break
                        # Check nested monitors (CombinedMonitor wraps actual monitors)
                        if hasattr(monitor, "monitors") and monitor.monitors:
                            for child_monitor in monitor.monitors:
                                # Check crashed state (ProtocolMonitor pattern)
                                if getattr(child_monitor, "crashed", False):
                                    result = "crash"
                                    child_crash_info = getattr(child_monitor, "crash_info", None)
                                    if child_crash_info:
                                        crash_info = f"Monitor crash: {child_crash_info.get('target', 'unknown')} at {child_crash_info.get('timestamp', 'unknown')}"
                                    else:
                                        crash_info = f"Monitor detected crash (consecutive_failures={getattr(child_monitor, 'consecutive_failures', 0)})"
                                    break
                                # Fallback: check consecutive_failures (for legacy monitors)
                                if (
                                    hasattr(child_monitor, "consecutive_failures")
                                    and child_monitor.consecutive_failures > 0
                                ):
                                    result = "crash"
                                    crash_info = f"Monitor detected {child_monitor.consecutive_failures} consecutive failures"
                                    break
                            if result == "crash":
                                break

                # Record the test case
                self.record_test_case(
                    test_id=test_case_id,
                    name=test_case_name,
                    payload=payload,
                    result=result,
                    duration_ms=None,  # Could calculate if needed
                    monitor_status="unknown",  # Could extract from monitors
                    crash_info=crash_info,
                )

            except Exception as e:
                self._log.fail(f"Failed to record test case: {e}")

        # Register the callback with the fuzzer's session using boofuzz API
        if hasattr(self.fuzzer, "session") and self.fuzzer.session:
            self.fuzzer.session.register_post_test_case_callback(record_callback)
            self._log.display("Test case recording callback registered")
        else:
            self._log.warning("Cannot register callbacks: fuzzer session not initialized")

    def _format_data(self, data: bytes, format_type: str = "hex") -> str:
        """Format binary data in different representations"""
        if not isinstance(data, bytes):
            data = bytes(data) if not isinstance(data, str) else data.encode()

        formats = {
            "hex": lambda d: " ".join(f"{b:02x}" for b in d),
            "base64": lambda d: __import__("base64").b64encode(d).decode(),
            "hexdump": hexdump,
        }
        return formats.get(format_type, str)(data)

    def list_test_cases(self, result_filter: Optional[str] = None) -> List[TestCase]:
        """
        List all test cases from the session database.

        Args:
            result_filter: Optional filter ('pass', 'fail', 'crash', 'error')

        Returns:
            List of test cases
        """
        try:
            test_cases = self.database.get_test_cases(result_filter=result_filter)

            self._log.display("\nAvailable Test Cases:")
            self._log.display("=" * 100)
            self._log.display(
                f"{'Name':<30} | {'ID':^8} | {'Result':^10} | {'Timestamp':^20} | {'CRC32':^10}"
            )
            self._log.display("-" * 100)

            for case in test_cases:
                self._log.display(
                    f"{case.name:<30} | {case.id:^8} | {case.result:^10} | {case.timestamp:^20} | {case.crc32:^10x}"
                )

            self._log.display(f"\nTotal: {len(test_cases)} test case(s)")

            # Show session stats
            stats = self.database.get_stats()
            self._log.display("\nSession Statistics:")
            self._log.display(f"  Passed: {stats['passed']}")
            self._log.display(f"  Failed: {stats['failed']}")
            self._log.display(f"  Crashed: {stats['crashed']}")
            self._log.display(f"  Errors: {stats['errors']}")
            self._log.display(f"  Database size: {stats['db_size_mb']} MB")

            return test_cases

        except Exception as e:
            self._log.fail(f"Error reading database: {e}")
            self._log.fail(f"Database read error: {e}")
            return []

    def get_test_case_details(self, test_case_id: int, show_data: bool = True) -> None:
        """Print detailed information about a specific test case to console"""
        try:
            # Get test case metadata
            case = self.database.get_test_case(test_case_id)

            if not case:
                self._log.display(f"Test case {test_case_id} not found")
                return

            self._log.display("\nTest Case Details")
            self._log.display("=" * 80)
            self._log.display(f"Test Case ID: {case.id}")
            self._log.display(f"Name: {case.name}")
            self._log.display(f"Result: {case.result}")
            self._log.display(f"Timestamp: {case.timestamp}")
            self._log.display(f"CRC32: {case.crc32:08x}")
            if case.duration_ms:
                self._log.display(f"Duration: {case.duration_ms:.2f} ms")
            if case.monitor_status:
                self._log.display(f"Monitor Status: {case.monitor_status}")
            self._log.display("=" * 80)

            # Check if payload is stored (crash or full storage mode)
            crash = self.database.get_crash(test_case_id)

            if crash:
                self._log.display(
                    f"\n{'Payload Stored: YES (crash/failure)' if case.result != 'pass' else 'Payload Stored: YES (--store-all-payloads mode)'}"
                )

                if show_data:
                    self._log.display("\nPayload Data:")
                    self._log.display("-" * 80)
                    self._log.display("\nHexdump:")
                    self._log.display(self._format_data(crash.payload, "hexdump"))
                    self._log.display("\nHex:")
                    self._log.display(self._format_data(crash.payload, "hex"))
                    self._log.display("\nBase64:")
                    self._log.display(self._format_data(crash.payload, "base64"))
                    self._log.display(f"\nPayload size: {len(crash.payload)} bytes")

                    if crash.crash_info:
                        self._log.display("\nCrash Information:")
                        self._log.display("-" * 80)
                        self._log.display(crash.crash_info)
            else:
                self._log.display(
                    "\nPayload Stored: NO (lightweight mode - can regenerate using boofuzz determinism)"
                )
                self._log.display(
                    f"To replay this test case, the fuzzer will regenerate the payload using index={test_case_id}"
                )

        except Exception as e:
            self._log.fail(f"Error getting test case details: {e}")
            self._log.fail(f"Error getting details for test case {test_case_id}: {e}")

    def replay_test_case(
        self,
        test_case_id: int,
        show_detail: bool = False,
        check_response: bool = False,
        validate_crc: bool = True,
    ) -> bool:
        """
        Replay a specific test case.

        For lightweight mode:
        - If crash: Use stored payload
        - If pass: Regenerate payload deterministically using boofuzz

        Args:
            test_case_id: Test case ID to replay
            show_detail: Show detailed output
            check_response: Validate responses
            validate_crc: Validate CRC32 matches (for regenerated payloads)

        Returns:
            bool: True if replay successful
        """
        try:
            # Get test case metadata
            case = self.database.get_test_case(test_case_id)
            if not case:
                self._log.display(f"Test case {test_case_id} not found")
                return False

            self._log.display(f"\nReplaying test case {test_case_id}: {case.name}")
            self._log.display(f"Result: {case.result} | CRC32: {case.crc32:08x}")

            # Check if payload is stored (crash or full storage)
            crash = self.database.get_crash(test_case_id)

            if crash:
                # Use stored crash payload
                payload = crash.payload
                self._log.display(f"Using stored payload ({len(payload)} bytes)")

                if show_detail:
                    self._log.display("\nStored Payload:")
                    self._log.display(self._format_data(payload, "hexdump"))

            else:
                # Check for stored payload in payloads table (store_all_payloads mode)
                stored = self.database.get_payload(test_case_id)
                if stored and stored.get("request") is not None:
                    payload = stored["request"]
                    self._log.display(f"Using stored payload ({len(payload)} bytes)")

                    if show_detail:
                        self._log.display("\nStored Payload:")
                        self._log.display(self._format_data(payload, "hexdump"))

                else:
                    # Regenerate payload deterministically
                    self._log.display(
                        f"Regenerating payload using boofuzz determinism (index={test_case_id})..."
                    )

                    try:
                        payload = self.fuzzer._regenerate_payload(test_case_id)
                    except AttributeError:
                        self._log.fail("Error: Fuzzer does not support payload regeneration")
                        self._log.display(
                            f"   The _regenerate_payload() method is not implemented in {type(self.fuzzer).__name__}"
                        )
                        return False

                    # Validate CRC32 matches
                    if validate_crc:
                        regenerated_crc = binascii.crc32(payload) & 0xFFFFFFFF

                        if regenerated_crc != case.crc32:
                            self._log.fail("CRC32 mismatch!")
                            self._log.display(f"   Expected: {case.crc32:08x}")
                            self._log.display(f"   Got:      {regenerated_crc:08x}")
                            self._log.display(
                                "   Protocol definition may have changed since recording."
                            )
                            self._log.display("   Check git commit hash in session metadata.")
                            return False

                        self._log.display(f"CRC32 validated: {regenerated_crc:08x}")

                    if show_detail:
                        self._log.display("\nRegenerated Payload:")
                        self._log.display(self._format_data(payload, "hexdump"))

            # Create and open the socket connection. open() belongs INSIDE the
            # try/finally: when replaying against a target that is down (the common
            # case for a crash replay) it raises, and the socket object was then
            # never closed -- leaking an fd per case across a replayed range.
            socket = self.fuzzer._create_socket()

            try:
                socket.open()

                # Send payload
                if show_detail:
                    self._log.display("\nSending payload...")

                sent_bytes = socket.send(payload)
                self._log.display(f"Sent {sent_bytes} bytes")

                # Handle response if requested
                if check_response:
                    try:
                        response = socket.recv(4096)
                        self._log.display(f"Response received: {len(response)} bytes")

                        if show_detail and response:
                            self._log.display("\nResponse data:")
                            self._log.display(self._format_data(response, "hexdump"))

                    except Exception as e:
                        self._log.fail(f"Error receiving response: {e}")
                        if check_response:
                            return False

                self._log.display("=" * 60)
                self._log.display(f"Test case {test_case_id} replay completed successfully")
                return True

            except Exception as e:
                self._log.fail(f"Error during replay: {e}")
                self._log.fail(f"Replay error for test case {test_case_id}: {e}")
                return False
            finally:
                socket.close()

        except Exception as e:
            self._log.fail(f"Error during replay setup: {e}")
            self._log.fail(f"Replay setup error for test case {test_case_id}: {e}")
            return False

    def replay_test_cases(
        self, test_range: str, show_detail: bool, check_response: bool = False
    ) -> list:
        """Replay multiple test cases with progress reporting"""
        try:
            test_ids = self.parse_test_case_range(test_range)
        except ValueError as e:
            self._log.fail(f"Error parsing range '{test_range}': {e}")
            return []

        if not test_ids:
            self._log.display("No test cases to replay")
            return []

        self._log.display(f"\nStarting replay of {len(test_ids)} test case(s): {test_range}")
        self._log.display("=" * 60)

        results = []
        successful = 0
        failed = 0

        for i, test_id in enumerate(test_ids, 1):
            self._log.display(f"\n[{i}/{len(test_ids)}] Processing test case {test_id}...")

            try:
                success = self.replay_test_case(test_id, show_detail, check_response)
                results.append((test_id, success))

                if success:
                    successful += 1
                    self._log.display(f"Test case {test_id} completed successfully")
                else:
                    failed += 1
                    self._log.fail(f"Test case {test_id} failed")

            except Exception as e:
                self._log.fail(f"Test case {test_id} failed with exception: {e}")
                self._log.fail(f"Exception replaying test case {test_id}: {e}")
                results.append((test_id, False))
                failed += 1

        # Summary
        self._log.display("\n" + "=" * 60)
        self._log.display("Replay Summary:")
        self._log.display(f"   Total test cases: {len(test_ids)}")
        self._log.display(f"   Successful: {successful}")
        self._log.fail(f"   Failed: {failed}")
        self._log.display(f"   Success rate: {(successful / len(test_ids) * 100):.1f}%")

        return results

    @staticmethod
    def parse_test_case_range(range_str: str) -> list:
        """Parse a test case range string into a list of IDs"""
        try:
            if "-" in range_str:
                start, end = map(int, range_str.split("-"))
                return list(range(start, end + 1))
            return [int(range_str)]
        except ValueError:
            raise ValueError("Invalid range format. Use 'N' or 'N-M'")


def create_fuzzer(protocol: str, config: FuzzerConfig) -> BaseFuzzer:
    """Create a fuzzer instance for the given protocol"""
    if protocol not in PROTOCOL_FUZZERS:
        raise ValueError(
            f"Unsupported protocol: {protocol}. Supported: {list(PROTOCOL_FUZZERS.keys())}"
        )

    if not config.session_filename:
        config.session_filename = f"{protocol}_{config.target_ip}_{config.target_port}_session"

    return PROTOCOL_FUZZERS[protocol](config)
