"""
Shared pytest fixtures for unit tests.

Inherits fixtures from parent conftest.py automatically via pytest's conftest discovery.
"""

import pytest
from pathlib import Path

# Fixtures directory for unit tests
FIXTURES_DIR = Path(__file__).parent.parent / "fixtures"


@pytest.fixture(scope="session")
def fixtures_dir():
    """Path to test fixtures directory."""
    return FIXTURES_DIR
