"""Pytest fixtures for the KNX mixin unit tests.

The reusable harness lives in ``tests/unit/knx/_harness.py`` (importable
as a module).  This conftest only wires the harness builders up as
fixtures so individual test modules can request ``host`` /
``patch_xknx_cls`` etc.
"""

import pytest

from tests.unit.knx._harness import KnxHost, SpyLogger, install_fake_xknx_cls


@pytest.fixture
def spy_logger():
    return SpyLogger()


@pytest.fixture
def host(spy_logger):
    return KnxHost(logger=spy_logger)


@pytest.fixture
def patch_xknx_cls(monkeypatch):
    return install_fake_xknx_cls(monkeypatch)
