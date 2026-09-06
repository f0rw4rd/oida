"""
Logging configuration for OIDA fuzzer.

Provides centralized logging setup with hierarchical loggers and
configurable output formatting for different contexts.
"""

import logging
import os
import sys
from typing import Optional


class CleanFormatter(logging.Formatter):
    """Clean formatter for user-facing output without timestamps/levels."""

    def format(self, record):
        return record.getMessage()


class StandardFormatter(logging.Formatter):
    """Standard formatter with timestamps and levels for file/debug output."""

    def __init__(self):
        super().__init__(
            fmt="%(asctime)s - %(name)s - %(levelname)s - %(message)s", datefmt="%Y-%m-%d %H:%M:%S"
        )


def get_logger(name: str) -> logging.Logger:
    """
    Get a logger instance with the given name.

    Args:
        name: Logger name (typically __name__ from calling module)

    Returns:
        Configured logger instance
    """
    return logging.getLogger(name)


def setup_logging(
    level: Optional[str] = None, log_file: Optional[str] = None, clean_output: bool = True
):
    """
    Configure logging for OIDA fuzzer.

    Args:
        level: Log level (DEBUG, INFO, WARNING, ERROR).
               Defaults to INFO, or OIDA_FUZZ_LOG_LEVEL env var
        log_file: Optional file path for log output
        clean_output: If True, console output uses clean formatting without
                     timestamps/levels (for user-facing CLI). If False, uses
                     standard formatting with timestamps.
    """
    # Determine log level
    if level is None:
        level = os.environ.get("OIDA_FUZZ_LOG_LEVEL", "INFO")

    log_level = getattr(logging, level.upper(), logging.INFO)

    # Get root oida.fuzz logger
    logger = logging.getLogger("oida.fuzz")
    logger.setLevel(log_level)

    # Remove existing handlers to avoid duplicates
    logger.handlers.clear()

    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(log_level)

    if clean_output:
        console_handler.setFormatter(CleanFormatter())
    else:
        console_handler.setFormatter(StandardFormatter())

    logger.addHandler(console_handler)

    # File handler (if specified)
    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(log_level)
        file_handler.setFormatter(StandardFormatter())
        logger.addHandler(file_handler)

    # Prevent propagation to root logger
    logger.propagate = False

    return logger


def set_level(level: str):
    """
    Change the logging level dynamically.

    Args:
        level: New log level (DEBUG, INFO, WARNING, ERROR)
    """
    log_level = getattr(logging, level.upper(), logging.INFO)
    logger = logging.getLogger("oida.fuzz")
    logger.setLevel(log_level)
    for handler in logger.handlers:
        handler.setLevel(log_level)


# Initialize default logging on module import
# This ensures logging is available even if setup_logging() isn't called explicitly
_default_logger = logging.getLogger("oida.fuzz")
if not _default_logger.handlers:
    setup_logging()
