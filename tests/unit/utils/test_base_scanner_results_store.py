"""BaseScanner.results is a plain dict with a fixed collection schema.

Before this it was a ``defaultdict(list)``: it silently autovivified *any* key
to an empty list (a footgun that masked typo'd reads), and it was a different
container type than the Layer-2 ``connection.results`` dict, so a subclass
returning ``get_results() -> ScanResult`` cast across incompatible types. The
store is now a plain dict with the four report_* collections pre-seeded.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any, Dict

import pytest

from oida.utils.base_scanner import BaseScanner


class _StubScanner(BaseScanner):
    """Minimal concrete BaseScanner - satisfies the six abstract methods."""

    def get_protocol_name(self) -> str:
        return "stub"

    def get_default_port(self) -> int:
        return 9999

    def check_dependencies(self) -> bool:
        return True

    def connect(self) -> Any:
        return object()

    def disconnect(self, connection: Any) -> None:
        pass

    def discover(self, connection: Any) -> Dict[str, Any]:
        return {}


@pytest.fixture
def scanner() -> _StubScanner:
    return _StubScanner({"rhost": "10.0.0.1", "rport": 9999})


def test_results_is_plain_dict_not_defaultdict(scanner):
    assert type(scanner.results) is dict
    assert not isinstance(scanner.results, defaultdict)


def test_four_collections_are_pre_seeded_empty(scanner):
    assert scanner.results["hosts"] == []
    assert scanner.results["services"] == []
    assert scanner.results["vulnerabilities"] == []
    assert scanner.results["credentials"] == []


def test_unknown_key_raises_instead_of_autovivifying(scanner):
    # The footgun: a defaultdict would have returned [] and created the entry.
    with pytest.raises(KeyError):
        _ = scanner.results["hsots"]  # typo of "hosts"
    assert "hsots" not in scanner.results


def test_report_helpers_still_append(scanner):
    scanner.report_host_info("10.0.0.1", detail="up")
    scanner.report_service_info("10.0.0.1", service="modbus")
    scanner.report_vulnerability("10.0.0.1", "CVE-2020-0001")
    scanner.report_credential("admin", "admin")

    assert len(scanner.results["hosts"]) == 1
    assert len(scanner.results["services"]) == 1
    assert len(scanner.results["vulnerabilities"]) == 1
    assert len(scanner.results["credentials"]) == 1


def test_report_credential_retains_the_discovered_password(scanner):
    # Regression: the discovered password (the deliverable of an authorized
    # scan) was silently dropped - only **kwargs reached the stored record.
    scanner.report_credential("operator", "s3cr3t!", host="10.0.0.1", port=502)

    record = scanner.results["credentials"][0]["10.0.0.1:operator"]
    assert record["username"] == "operator"
    assert record["password"] == "s3cr3t!"
    assert record["port"] == 502
