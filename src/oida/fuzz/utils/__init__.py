"""Fuzzer utilities"""

import subprocess

from ...utils.ics_logger import get_logger

_log = get_logger("FUZZ", "utils", 0)


def get_git_commit_hash() -> str:
    """Get the current git commit hash, or 'unknown' if not in a git repo"""
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"], capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            return result.stdout.strip()
    except Exception as e:
        _log.debug(f"Failed to get git commit hash: {e}")
    return "unknown"


__all__ = ["get_git_commit_hash"]
